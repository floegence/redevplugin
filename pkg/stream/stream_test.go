package stream

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
)

func TestMemoryStoreRegisterAppendReadAndClose(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record, err := store.Register(context.Background(), RegisterRequest{
		StreamID:         "stream_1",
		ExecutionBinding: streamTestBinding("plugini_1"),
		MaxBufferedBytes: 96,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if record.Direction != DirectionRead || record.Status != StatusOpen || record.MaxBufferedBytes != 96 {
		t.Fatalf("registered record mismatch: %#v", record)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("hello"), Now: now.Add(time.Second)}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("world"), Now: now.Add(2 * time.Second)}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_1", Data: []byte("0123456789abcdef"), Now: now.Add(3 * time.Second)}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("Append() error = %v, want ErrBackpressure", err)
	}
	wantBuffered := streamEventCost(Event{Kind: "data", Data: []byte("hello")}) + streamEventCost(Event{Kind: "data", Data: []byte("world")})
	record, delivery, err := store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_1", ReadID: "read_memory_1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if len(delivery.Events) != 1 || string(delivery.Events[0].Data) != "hello" || delivery.DeliveryID == "" || record.BufferedBytes != wantBuffered {
		t.Fatalf("first delivery mismatch: record=%#v delivery=%#v", record, delivery)
	}
	_, replayed, err := store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_1", ReadID: "read_memory_retry"})
	if err != nil {
		t.Fatalf("Deliver(replay) error = %v", err)
	}
	if replayed.DeliveryID != delivery.DeliveryID || replayed.ReadID != delivery.ReadID || string(replayed.Events[0].Data) != "hello" {
		t.Fatalf("replayed delivery mismatch: %#v", replayed)
	}
	record, err = store.Acknowledge(context.Background(), AcknowledgeRequest{StreamID: "stream_1", DeliveryID: delivery.DeliveryID})
	if err != nil || record.BufferedBytes != streamEventCost(Event{Kind: "data", Data: []byte("world")}) {
		t.Fatalf("Acknowledge(first) record=%#v err=%v", record, err)
	}
	record, delivery, err = store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_1", ReadID: "read_memory_2"})
	if err != nil || len(delivery.Events) != 1 || string(delivery.Events[0].Data) != "world" {
		t.Fatalf("second delivery mismatch: record=%#v delivery=%#v err=%v", record, delivery, err)
	}
	record, err = store.Acknowledge(context.Background(), AcknowledgeRequest{StreamID: "stream_1", DeliveryID: delivery.DeliveryID})
	if err != nil || record.BufferedBytes != 0 {
		t.Fatalf("Acknowledge(second) record=%#v err=%v", record, err)
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

func TestStoresRequireClosedFailureCodes(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		for _, streamID := range []string{"stream_reason", "stream_unknown", "stream_closed", "stream_valid"} {
			if _, err := store.Register(ctx, RegisterRequest{StreamID: streamID, ExecutionBinding: streamTestBinding("plugini_failure")}); err != nil {
				t.Fatal(err)
			}
		}

		if _, err := store.Close(ctx, CloseRequest{StreamID: "stream_reason", Status: StatusFailed, Reason: "private adapter detail"}); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("failed reason error = %v, want ErrInvalidStream", err)
		}
		if _, err := store.Close(ctx, CloseRequest{StreamID: "stream_unknown", Status: StatusFailed, FailureCode: "internal"}); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("unknown failure code error = %v, want ErrInvalidStream", err)
		}
		if _, err := store.Close(ctx, CloseRequest{StreamID: "stream_closed", Status: StatusClosed, FailureCode: capability.ExecutionFailurePlatformFailed}); !errors.Is(err, ErrInvalidStream) {
			t.Fatalf("non-failed failure code error = %v, want ErrInvalidStream", err)
		}
		failed, err := store.Close(ctx, CloseRequest{StreamID: "stream_valid", Status: StatusFailed, FailureCode: capability.ExecutionFailureRuntimeFailed})
		if err != nil {
			t.Fatal(err)
		}
		if failed.FailureCode != capability.ExecutionFailureRuntimeFailed || failed.Reason != capability.ExecutionFailureMessage {
			t.Fatalf("closed failure = %#v", failed)
		}
	})
}

func TestStoresRejectInvalidReadIDs(t *testing.T) {
	ctx := context.Background()
	stores := map[string]Store{
		"memory": NewMemoryStore(),
	}
	sqliteStore, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "invalid-read-id.sqlite"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	defer func() {
		if err := sqliteStore.CloseDatabase(); err != nil {
			t.Errorf("CloseDatabase() error = %v", err)
		}
	}()
	stores["sqlite"] = sqliteStore

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Register(ctx, RegisterRequest{
				StreamID:         "stream_invalid_read_id_" + name,
				ExecutionBinding: streamTestBinding("plugini_invalid_read_id"),
			}); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			for _, readID := range []string{"", "read_short", "read_invalid!value", "other_12345678"} {
				if _, _, err := store.Deliver(ctx, DeliverRequest{
					StreamID: "stream_invalid_read_id_" + name,
					ReadID:   readID,
				}); !errors.Is(err, ErrInvalidStream) {
					t.Fatalf("Deliver(read_id=%q) error = %v, want ErrInvalidStream", readID, err)
				}
			}
		})
	}
}

func TestStoresRejectWrongDeliveryIDAndReplayPendingDelivery(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		const streamID = "stream_wrong_delivery"
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         streamID,
			ExecutionBinding: streamTestBinding("plugini_wrong_delivery"),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("first")}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("second")}); err != nil {
			t.Fatal(err)
		}

		record, pending, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_wrong_delivery_1", MaxEvents: 1})
		if err != nil {
			t.Fatal(err)
		}
		bufferedBeforeAck := record.BufferedBytes
		if _, err := store.Acknowledge(ctx, AcknowledgeRequest{
			StreamID: streamID, DeliveryID: "delivery_wrong_00000001",
		}); !errors.Is(err, ErrDeliveryInvalid) {
			t.Fatalf("Acknowledge(wrong delivery) error = %v, want ErrDeliveryInvalid", err)
		}
		afterWrongAck, err := store.Get(ctx, streamID)
		if err != nil {
			t.Fatal(err)
		}
		if afterWrongAck.BufferedBytes != bufferedBeforeAck {
			t.Fatalf("wrong acknowledgement changed buffered bytes: got %d want %d", afterWrongAck.BufferedBytes, bufferedBeforeAck)
		}
		_, replayed, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_wrong_delivery_2", MaxEvents: 2})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(replayed, pending) {
			t.Fatalf("pending delivery changed after wrong acknowledgement:\n got %#v\nwant %#v", replayed, pending)
		}
	})
}

func TestStoresRetryAcknowledgementWithoutDeletingNextDelivery(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		const streamID = "stream_ack_retry"
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         streamID,
			ExecutionBinding: streamTestBinding("plugini_ack_retry"),
		}); err != nil {
			t.Fatal(err)
		}
		secondCost := streamEventCost(Event{Kind: "data", Data: []byte("second")})
		for _, value := range []string{"first", "second"} {
			if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte(value)}); err != nil {
				t.Fatal(err)
			}
		}

		_, first, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_ack_retry_1", MaxEvents: 1})
		if err != nil {
			t.Fatal(err)
		}
		record, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: first.DeliveryID})
		if err != nil || record.BufferedBytes != secondCost {
			t.Fatalf("Acknowledge(first) record=%#v err=%v", record, err)
		}
		// The committed acknowledgement response may be lost in transport. Retrying
		// the same delivery must report success without applying the deletion twice.
		record, err = store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: first.DeliveryID})
		if err != nil || record.BufferedBytes != secondCost {
			t.Fatalf("Acknowledge(first retry) record=%#v err=%v", record, err)
		}

		_, second, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_ack_retry_2", MaxEvents: 1})
		if err != nil || len(second.Events) != 1 || string(second.Events[0].Data) != "second" {
			t.Fatalf("Deliver(second) delivery=%#v err=%v", second, err)
		}
		// A delayed retry of the previous ack is still idempotent while the next
		// delivery is pending, and must not acknowledge that next delivery.
		record, err = store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: first.DeliveryID})
		if err != nil || record.BufferedBytes != secondCost {
			t.Fatalf("Acknowledge(first delayed retry) record=%#v err=%v", record, err)
		}
		_, replayedSecond, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_ack_retry_3"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(replayedSecond, second) {
			t.Fatalf("retry of previous ack changed next delivery:\n got %#v\nwant %#v", replayedSecond, second)
		}
		record, err = store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: second.DeliveryID})
		if err != nil || record.BufferedBytes != 0 {
			t.Fatalf("Acknowledge(second) record=%#v err=%v", record, err)
		}
	})
}

func TestStoresReplayUnacknowledgedTerminalDeliveryExactly(t *testing.T) {
	tests := []struct {
		name        string
		status      Status
		appendError bool
	}{
		{name: "closed", status: StatusClosed},
		{name: "failed_with_error_event", status: StatusFailed, appendError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forEachStreamStore(t, func(t *testing.T, store Store) {
				ctx := context.Background()
				streamID := "stream_terminal_" + test.name
				if _, err := store.Register(ctx, RegisterRequest{
					StreamID:         streamID,
					ExecutionBinding: streamTestBinding("plugini_terminal"),
				}); err != nil {
					t.Fatal(err)
				}
				if test.appendError {
					if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Kind: "error", Error: "worker failed"}); err != nil {
						t.Fatal(err)
					}
				}
				closeRequest := CloseRequest{StreamID: streamID, Status: test.status, Reason: "terminal test"}
				if test.status == StatusFailed {
					closeRequest.FailureCode = capability.ExecutionFailureRuntimeFailed
					closeRequest.Reason = ""
				}
				if _, err := store.Close(ctx, closeRequest); err != nil {
					t.Fatal(err)
				}
				_, terminal, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_terminal_first"})
				if err != nil {
					t.Fatal(err)
				}
				if terminal.DeliveryID == "" || !terminal.Done || terminal.TerminalStatus != test.status {
					t.Fatalf("terminal delivery mismatch: %#v", terminal)
				}
				if test.appendError && (len(terminal.Events) != 1 || terminal.Events[0].Kind != "error" || terminal.Events[0].Error != "worker failed") {
					t.Fatalf("failed terminal event mismatch: %#v", terminal.Events)
				}
				_, replayed, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_terminal_retry"})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(replayed, terminal) {
					t.Fatalf("terminal delivery was not replayed exactly:\n got %#v\nwant %#v", replayed, terminal)
				}
				if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: terminal.DeliveryID}); err != nil {
					t.Fatal(err)
				}
				_, afterAck, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_terminal_after_ack"})
				if err != nil {
					t.Fatal(err)
				}
				if afterAck.ReadID != "read_terminal_after_ack" || afterAck.StreamID != streamID || afterAck.DeliveryID != "" || afterAck.Done || len(afterAck.Events) != 0 {
					t.Fatalf("acknowledged terminal stream returned another delivery: %#v", afterAck)
				}
			})
		})
	}
}

func TestStoresKeepBackpressureUntilPendingDeliveryIsAcknowledged(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		const streamID = "stream_pending_backpressure"
		eventCost := streamEventCost(Event{Kind: "data", Data: []byte("x")})
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         streamID,
			ExecutionBinding: streamTestBinding("plugini_pending_backpressure"),
			MaxBufferedBytes: 2 * eventCost,
		}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("x")}); err != nil {
				t.Fatal(err)
			}
		}
		record, pending, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_pending_pressure", MaxEvents: 1})
		if err != nil || record.BufferedBytes != 2*eventCost || len(pending.Events) != 1 {
			t.Fatalf("Deliver() record=%#v delivery=%#v err=%v", record, pending, err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("x")}); !errors.Is(err, ErrBackpressure) {
			t.Fatalf("Append(before ack) error = %v, want ErrBackpressure", err)
		}
		if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: pending.DeliveryID}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("x")}); err != nil {
			t.Fatalf("Append(after ack) error = %v", err)
		}
	})
}

func TestStoresBoundDeliveriesByMaxEventsAndMaxBytes(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		const maxEventsStreamID = "stream_max_events"
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         maxEventsStreamID,
			ExecutionBinding: streamTestBinding("plugini_read_bounds"),
		}); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"one", "two", "three"} {
			if _, err := store.Append(ctx, AppendRequest{StreamID: maxEventsStreamID, Data: []byte(value)}); err != nil {
				t.Fatal(err)
			}
		}
		_, byEvents, err := store.Deliver(ctx, DeliverRequest{StreamID: maxEventsStreamID, ReadID: "read_max_events", MaxEvents: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(byEvents.Events) != 2 || byEvents.Events[0].Sequence != 1 || byEvents.Events[1].Sequence != 2 {
			t.Fatalf("MaxEvents delivery mismatch: %#v", byEvents)
		}

		const maxBytesStreamID = "stream_max_bytes"
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         maxBytesStreamID,
			ExecutionBinding: streamTestBinding("plugini_read_bounds"),
		}); err != nil {
			t.Fatal(err)
		}
		first := Event{Kind: "data", Data: []byte("a")}
		second := Event{Kind: "data", Data: []byte("bb")}
		third := Event{Kind: "data", Data: []byte("ccc")}
		for _, event := range []Event{first, second, third} {
			if _, err := store.Append(ctx, AppendRequest{StreamID: maxBytesStreamID, Kind: event.Kind, Data: event.Data}); err != nil {
				t.Fatal(err)
			}
		}
		maxBytes := streamEventCost(first) + streamEventCost(second)
		_, byBytes, err := store.Deliver(ctx, DeliverRequest{StreamID: maxBytesStreamID, ReadID: "read_max_bytes_1", MaxEvents: 10, MaxBytes: maxBytes})
		if err != nil {
			t.Fatal(err)
		}
		if len(byBytes.Events) != 2 || byBytes.Events[1].Sequence != 2 || eventsCost(byBytes.Events) > maxBytes {
			t.Fatalf("MaxBytes delivery mismatch: max=%d cost=%d delivery=%#v", maxBytes, eventsCost(byBytes.Events), byBytes)
		}
		if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: maxBytesStreamID, DeliveryID: byBytes.DeliveryID}); err != nil {
			t.Fatal(err)
		}
		_, remaining, err := store.Deliver(ctx, DeliverRequest{StreamID: maxBytesStreamID, ReadID: "read_max_bytes_2", MaxBytes: maxBytes})
		if err != nil || len(remaining.Events) != 1 || remaining.Events[0].Sequence != 3 || string(remaining.Events[0].Data) != "ccc" {
			t.Fatalf("remaining bounded delivery=%#v err=%v", remaining, err)
		}
	})
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
	if changed.Changed != 2 {
		t.Fatalf("changed streams = %d, want 2", changed.Changed)
	}
	for _, streamID := range []string{"stream_a", "stream_b"} {
		record, err := store.Get(context.Background(), streamID)
		if err != nil {
			t.Fatal(err)
		}
		if record.Status != StatusOrphanedDisabled || record.Reason != "policy" {
			t.Fatalf("changed stream %s mismatch: %#v", streamID, record)
		}
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
	_, delivery, err := store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_event_clone", ReadID: "read_clone_event"})
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Events) != 1 || string(delivery.Events[0].Data) != "original" {
		t.Fatalf("stored stream event was mutated through Append(): %#v", delivery.Events)
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
			binding.OwnerEnvHash = "owner_env"
			binding.SessionChannelIDHash = "channel_hash"
			binding.BridgeChannelID = "bridge_channel"
		}),
		ContentType:      "text/plain",
		MaxBufferedBytes: 128,
		Now:              now,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if record.Status != StatusOpen || record.Direction != DirectionRead || record.MaxBufferedBytes != 128 {
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
	persisted, err := reopened.Get(ctx, "stream_sqlite_1")
	if err != nil {
		t.Fatalf("Get() after reopen error = %v", err)
	}
	if persisted.PluginInstanceID != "plugini_sqlite" ||
		persisted.SurfaceInstanceID != "surface_1" ||
		persisted.OwnerSessionHash != "owner_session" ||
		persisted.OwnerEnvHash != "owner_env" ||
		persisted.BufferedBytes != streamEventCost(Event{Kind: "data", Data: []byte("alpha")})+streamEventCost(Event{Kind: "data", Data: []byte("beta")}) {
		t.Fatalf("persisted record mismatch: %#v", persisted)
	}
	persisted, delivery, err := reopened.Deliver(ctx, DeliverRequest{StreamID: "stream_sqlite_1", ReadID: "read_sqlite_1", MaxEvents: 1})
	if err != nil {
		t.Fatalf("Deliver(first) error = %v", err)
	}
	wantBuffered := streamEventCost(Event{Kind: "data", Data: []byte("alpha")}) + streamEventCost(Event{Kind: "data", Data: []byte("beta")})
	if len(delivery.Events) != 1 || delivery.Events[0].Sequence != 1 || string(delivery.Events[0].Data) != "alpha" || persisted.BufferedBytes != wantBuffered {
		t.Fatalf("first delivery mismatch: record=%#v delivery=%#v", persisted, delivery)
	}
	if err := reopened.CloseDatabase(); err != nil {
		t.Fatalf("Close(reopened) error = %v", err)
	}
	replayedStore, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("replay NewSQLiteStore() error = %v", err)
	}
	defer func() { _ = replayedStore.CloseDatabase() }()
	_, replayed, err := replayedStore.Deliver(ctx, DeliverRequest{StreamID: "stream_sqlite_1", ReadID: "read_sqlite_retry"})
	if err != nil || replayed.DeliveryID != delivery.DeliveryID || replayed.ReadID != delivery.ReadID || string(replayed.Events[0].Data) != "alpha" {
		t.Fatalf("replayed delivery mismatch: delivery=%#v err=%v", replayed, err)
	}
	persisted, err = replayedStore.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_sqlite_1", DeliveryID: delivery.DeliveryID})
	if err != nil || persisted.BufferedBytes != streamEventCost(Event{Kind: "data", Data: []byte("beta")}) {
		t.Fatalf("Acknowledge(first) record=%#v err=%v", persisted, err)
	}
	if _, err := replayedStore.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_sqlite_1", DeliveryID: delivery.DeliveryID}); err != nil {
		t.Fatalf("Acknowledge(retry) error = %v", err)
	}
	_, second, err := replayedStore.Deliver(ctx, DeliverRequest{StreamID: "stream_sqlite_1", ReadID: "read_sqlite_2"})
	if err != nil || len(second.Events) != 1 || second.Events[0].Sequence != 2 || string(second.Events[0].Data) != "beta" {
		t.Fatalf("second delivery mismatch: delivery=%#v err=%v", second, err)
	}
	if _, err := replayedStore.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_sqlite_1", DeliveryID: second.DeliveryID}); err != nil {
		t.Fatalf("Acknowledge(second) error = %v", err)
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
	if changed.Changed != 2 {
		t.Fatalf("changed streams = %d, want 2", changed.Changed)
	}
	for _, streamID := range []string{"stream_a", "stream_b"} {
		record, err := store.Get(ctx, streamID)
		if err != nil {
			t.Fatal(err)
		}
		if record.Status != StatusOrphanedRemoved || record.Reason != "uninstalled" {
			t.Fatalf("changed stream %s mismatch: %#v", streamID, record)
		}
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

func TestStoresWaitWithoutLostWakeups(t *testing.T) {
	tests := []struct {
		name string
		open func(t *testing.T) Store
	}{
		{name: "memory", open: func(t *testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "streams.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.CloseDatabase() })
			return store
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := test.open(t)
			if _, err := store.Register(context.Background(), RegisterRequest{StreamID: "stream_wait", ExecutionBinding: streamTestBinding("plugini_wait")}); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 100; attempt++ {
				waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				result := make(chan error, 1)
				go func() { result <- store.Wait(waitCtx, "stream_wait") }()
				if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_wait", Data: []byte("x")}); err != nil {
					cancel()
					t.Fatal(err)
				}
				if err := <-result; err != nil {
					cancel()
					t.Fatalf("Wait() attempt %d error = %v", attempt, err)
				}
				cancel()
				_, delivery, err := store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_wait", ReadID: fmt.Sprintf("read_wait_%08d", attempt), MaxEvents: 1})
				if err != nil || len(delivery.Events) != 1 {
					t.Fatalf("Deliver() attempt %d events=%d err=%v", attempt, len(delivery.Events), err)
				}
				if _, err := store.Acknowledge(context.Background(), AcknowledgeRequest{StreamID: "stream_wait", DeliveryID: delivery.DeliveryID}); err != nil {
					t.Fatalf("Acknowledge() attempt %d error=%v", attempt, err)
				}
			}
			cancelCtx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := store.Wait(cancelCtx, "stream_wait"); !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait(canceled) error = %v", err)
			}
			if _, err := store.Close(context.Background(), CloseRequest{StreamID: "stream_wait"}); err != nil {
				t.Fatal(err)
			}
			if err := store.Wait(context.Background(), "stream_wait"); err != nil {
				t.Fatalf("Wait(terminal) error = %v", err)
			}
		})
	}
}

func TestStoresWakeMultipleLongPollsAndIsolateConcurrentStreams(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		const sharedStreamID = "stream_shared_long_poll"
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         sharedStreamID,
			ExecutionBinding: streamTestBinding("plugini_long_poll_contract"),
		}); err != nil {
			t.Fatal(err)
		}

		const waiterCount = 24
		ready := make(chan struct{}, waiterCount)
		results := make(chan error, waiterCount)
		for range waiterCount {
			go func() {
				waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				ready <- struct{}{}
				results <- store.Wait(waitCtx, sharedStreamID)
			}()
		}
		for range waiterCount {
			<-ready
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: sharedStreamID, Data: []byte("broadcast")}); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < waiterCount; index++ {
			if err := <-results; err != nil {
				t.Fatalf("shared long poll %d error = %v", index, err)
			}
		}

		const streamCount = 24
		waitResults := make(chan error, streamCount)
		appendResults := make(chan error, streamCount)
		var appendWG sync.WaitGroup
		for index := 0; index < streamCount; index++ {
			streamID := fmt.Sprintf("stream_parallel_%02d", index)
			if _, err := store.Register(ctx, RegisterRequest{
				StreamID:         streamID,
				ExecutionBinding: streamTestBinding("plugini_parallel_streams"),
			}); err != nil {
				t.Fatal(err)
			}
			go func() {
				waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				waitResults <- store.Wait(waitCtx, streamID)
			}()
			appendWG.Add(1)
			go func() {
				defer appendWG.Done()
				_, err := store.Append(context.Background(), AppendRequest{StreamID: streamID, Data: []byte(streamID)})
				appendResults <- err
			}()
		}
		appendWG.Wait()
		for index := 0; index < streamCount; index++ {
			if err := <-appendResults; err != nil {
				t.Fatalf("parallel stream append %d error = %v", index, err)
			}
		}
		for index := 0; index < streamCount; index++ {
			if err := <-waitResults; err != nil {
				t.Fatalf("parallel stream wait %d error = %v", index, err)
			}
		}
		for index := 0; index < streamCount; index++ {
			streamID := fmt.Sprintf("stream_parallel_%02d", index)
			_, delivery, err := store.Deliver(ctx, DeliverRequest{
				StreamID: streamID,
				ReadID:   fmt.Sprintf("read_parallel_%08d", index),
			})
			if err != nil || len(delivery.Events) != 1 || string(delivery.Events[0].Data) != streamID {
				t.Fatalf("Deliver(%s) delivery=%#v err=%v", streamID, delivery, err)
			}
		}
	})
}

func TestStoresDoNotRetainNotificationsWithoutWaiters(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		const streamCount = 256
		for index := 0; index < streamCount; index++ {
			streamID := fmt.Sprintf("stream_no_waiter_%03d", index)
			if _, err := store.Register(context.Background(), RegisterRequest{
				StreamID:         streamID,
				ExecutionBinding: streamTestBinding("plugini_no_waiter"),
			}); err != nil {
				t.Fatal(err)
			}
		}
		switch typed := store.(type) {
		case *MemoryStore:
			if len(typed.notify) != 0 {
				t.Fatalf("memory store retained %d idle notification channels", len(typed.notify))
			}
		case *SQLiteStore:
			typed.notifyMu.Lock()
			retained := len(typed.notify)
			typed.notifyMu.Unlock()
			if retained != 0 {
				t.Fatalf("sqlite store retained %d idle notification channels", retained)
			}
		default:
			t.Fatalf("unexpected stream store %T", store)
		}
	})
}

func TestStoresReleaseCanceledIdleWaiters(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		const streamID = "stream_canceled_idle_waiters"
		const waiterCount = 16
		if _, err := store.Register(context.Background(), RegisterRequest{
			StreamID:         streamID,
			ExecutionBinding: streamTestBinding("plugini_canceled_idle_waiters"),
		}); err != nil {
			t.Fatal(err)
		}

		cancels := make([]context.CancelFunc, 0, waiterCount)
		results := make(chan error, waiterCount)
		for range waiterCount {
			waitCtx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			go func() { results <- store.Wait(waitCtx, streamID) }()
		}
		waitForNotificationState(t, store, streamID, 1, waiterCount)
		for _, cancel := range cancels {
			cancel()
		}
		for range waiterCount {
			if err := <-results; !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait(canceled) error = %v, want context.Canceled", err)
			}
		}
		waitForNotificationState(t, store, streamID, 0, 0)
	})
}

func TestStoresKeepSharedNotificationUntilLastWaiterLeaves(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		const streamID = "stream_shared_notification_lifecycle"
		if _, err := store.Register(context.Background(), RegisterRequest{
			StreamID:         streamID,
			ExecutionBinding: streamTestBinding("plugini_shared_notification_lifecycle"),
		}); err != nil {
			t.Fatal(err)
		}

		cancelCtx, cancel := context.WithCancel(context.Background())
		readyCtx, readyCancel := context.WithTimeout(context.Background(), time.Second)
		defer readyCancel()
		canceledResult := make(chan error, 1)
		readyResult := make(chan error, 1)
		go func() { canceledResult <- store.Wait(cancelCtx, streamID) }()
		go func() { readyResult <- store.Wait(readyCtx, streamID) }()
		waitForNotificationState(t, store, streamID, 1, 2)

		cancel()
		if err := <-canceledResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("first Wait() error = %v, want context.Canceled", err)
		}
		waitForNotificationState(t, store, streamID, 1, 1)
		if _, err := store.Append(context.Background(), AppendRequest{StreamID: streamID, Data: []byte("ready")}); err != nil {
			t.Fatal(err)
		}
		if err := <-readyResult; err != nil {
			t.Fatalf("remaining Wait() error = %v", err)
		}
		waitForNotificationState(t, store, streamID, 0, 0)
	})
}

func TestStoresPruneOnlyReplayCompleteTerminalStreams(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
		old := now.Add(-DefaultTerminalRetention - time.Hour)
		for _, streamID := range []string{"old-acknowledged", "old-replayable", "recent-acknowledged", "old-open"} {
			registeredAt := old
			if streamID == "recent-acknowledged" {
				registeredAt = now.Add(-time.Hour)
			}
			if _, err := store.Register(ctx, RegisterRequest{
				StreamID:         streamID,
				ExecutionBinding: streamTestBinding("plugini_prune"),
				Now:              registeredAt,
			}); err != nil {
				t.Fatal(err)
			}
		}
		for _, streamID := range []string{"old-acknowledged", "old-replayable", "recent-acknowledged"} {
			closedAt := old
			if streamID == "recent-acknowledged" {
				closedAt = now.Add(-time.Hour)
			}
			if _, err := store.Close(ctx, CloseRequest{StreamID: streamID, Now: closedAt}); err != nil {
				t.Fatal(err)
			}
		}
		for _, streamID := range []string{"old-acknowledged", "recent-acknowledged"} {
			_, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_" + strings.ReplaceAll(streamID, "-", "_")})
			if err != nil || !delivery.Done || delivery.DeliveryID == "" {
				t.Fatalf("Deliver(%s) = %#v, %v", streamID, delivery, err)
			}
			if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: delivery.DeliveryID}); err != nil {
				t.Fatal(err)
			}
		}

		result, err := store.Prune(ctx, PruneRequest{Before: now.Add(-DefaultTerminalRetention)})
		if err != nil || result.Deleted != 1 {
			t.Fatalf("Prune() = %#v, %v", result, err)
		}
		if _, err := store.Get(ctx, "old-acknowledged"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("acknowledged terminal Get() error = %v, want ErrNotFound", err)
		}
		for _, streamID := range []string{"old-replayable", "recent-acknowledged", "old-open"} {
			if _, err := store.Get(ctx, streamID); err != nil {
				t.Fatalf("Get(%s) after prune error = %v", streamID, err)
			}
		}
		_, replay, err := store.Deliver(ctx, DeliverRequest{StreamID: "old-replayable", ReadID: "read_old_replayable"})
		if err != nil || !replay.Done || replay.TerminalStatus != StatusClosed || replay.DeliveryID == "" {
			t.Fatalf("terminal replay after prune = %#v, %v", replay, err)
		}
	})
}

func TestStoresBoundRecentReplayCompleteStreamsPerPlugin(t *testing.T) {
	forEachStreamStore(t, func(t *testing.T, store Store) {
		ctx := context.Background()
		now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
		registerTerminal := func(streamID, pluginInstanceID string, acknowledge bool) {
			t.Helper()
			if _, err := store.Register(ctx, RegisterRequest{StreamID: streamID, ExecutionBinding: streamTestBinding(pluginInstanceID), Now: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Close(ctx, CloseRequest{StreamID: streamID, Now: now}); err != nil {
				t.Fatal(err)
			}
			if !acknowledge {
				return
			}
			_, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_" + streamID})
			if err != nil || delivery.DeliveryID == "" || !delivery.Done {
				t.Fatalf("Deliver(%s) = %#v, %v", streamID, delivery, err)
			}
			if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: delivery.DeliveryID}); err != nil {
				t.Fatal(err)
			}
		}
		for index := 0; index < 5; index++ {
			registerTerminal(fmt.Sprintf("stream_cap_a_%d", index), "plugin_cap_a", true)
		}
		registerTerminal("stream_cap_a_replay", "plugin_cap_a", false)
		for index := 0; index < 2; index++ {
			registerTerminal(fmt.Sprintf("stream_cap_b_%d", index), "plugin_cap_b", true)
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
			if _, err := store.Get(ctx, fmt.Sprintf("stream_cap_a_%d", index)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("capped stream %d error = %v, want ErrNotFound", index, err)
			}
		}
		for _, streamID := range []string{"stream_cap_a_3", "stream_cap_a_4", "stream_cap_a_replay", "stream_cap_b_0", "stream_cap_b_1"} {
			if _, err := store.Get(ctx, streamID); err != nil {
				t.Fatalf("retained stream %s error = %v", streamID, err)
			}
		}
		_, replay, err := store.Deliver(ctx, DeliverRequest{StreamID: "stream_cap_a_replay", ReadID: "read_stream_cap_a_replay_retry"})
		if err != nil || !replay.Done || replay.DeliveryID == "" {
			t.Fatalf("unacknowledged replay after cap = %#v, %v", replay, err)
		}
	})
}

func TestSQLiteStorePerStreamLocksAreIndependentAndCancelable(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	for _, streamID := range []string{"stream_locked", "stream_other"} {
		if _, err := store.Register(ctx, RegisterRequest{StreamID: streamID, ExecutionBinding: streamTestBinding("plugini_locks")}); err != nil {
			t.Fatal(err)
		}
	}

	release, err := store.lockStream(ctx, "stream_locked")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	otherDone := make(chan error, 1)
	go func() {
		_, getErr := store.Get(context.Background(), "stream_other")
		otherDone <- getErr
	}()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("Get(other stream) error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation on another stream was blocked by the held stream lock")
	}

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := store.Get(waitCtx, "stream_locked"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get(locked stream) error = %v, want context deadline", err)
	}

	releaseWrite, err := store.lockWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writeCtx, writeCancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer writeCancel()
	if _, err := store.Append(writeCtx, AppendRequest{StreamID: "stream_other", Data: []byte("blocked")}); !errors.Is(err, context.DeadlineExceeded) {
		releaseWrite()
		t.Fatalf("Append(waiting for write gate) error = %v, want context deadline", err)
	}
	releaseWrite()
}

func TestSQLiteStoreWakesOneHundredConcurrentLongPolls(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })

	const streamCount = 100
	results := make(chan error, streamCount)
	for index := 0; index < streamCount; index++ {
		streamID := fmt.Sprintf("stream_long_poll_%03d", index)
		if _, err := store.Register(ctx, RegisterRequest{StreamID: streamID, ExecutionBinding: streamTestBinding("plugini_long_poll")}); err != nil {
			t.Fatal(err)
		}
		go func() {
			waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results <- store.Wait(waitCtx, streamID)
		}()
	}
	var wg sync.WaitGroup
	for index := 0; index < streamCount; index++ {
		streamID := fmt.Sprintf("stream_long_poll_%03d", index)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, appendErr := store.Append(context.Background(), AppendRequest{StreamID: streamID, Data: []byte("ready")})
			if appendErr != nil {
				results <- appendErr
			}
		}()
	}
	wg.Wait()
	for index := 0; index < streamCount; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("long poll %d error = %v", index, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("long poll %d did not wake", index)
		}
	}
}

func TestSQLiteStorePluginTransitionWakesAllRegisteredLongPolls(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })

	const waiterCount = 100
	const streamID = "stream_transition_waiters"
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID: streamID, ExecutionBinding: streamTestBinding("plugini_transition_waiters"),
	}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, waiterCount)
	for range waiterCount {
		go func() {
			waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results <- store.Wait(waitCtx, streamID)
		}()
	}
	waitForNotificationState(t, store, streamID, 1, waiterCount)
	transition, err := store.MarkPluginTransition(ctx, PluginTransitionRequest{
		PluginInstanceID: "plugini_transition_waiters", Status: StatusOrphanedRemoved, Reason: "plugin removed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if transition.Changed != 1 {
		t.Fatalf("MarkPluginTransition() changed = %d, want 1", transition.Changed)
	}
	for index := 0; index < waiterCount; index++ {
		if err := <-results; err != nil {
			t.Fatalf("transition waiter %d error = %v", index, err)
		}
	}
	waitForNotificationState(t, store, streamID, 0, 0)
}

func TestSQLiteStoreWaitDoesNotLoseConcurrentPluginTransition(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })

	const streamID = "stream_transition_during_observation"
	const pluginInstanceID = "plugini_transition_during_observation"
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         streamID,
		ExecutionBinding: streamTestBinding(pluginInstanceID),
	}); err != nil {
		t.Fatal(err)
	}

	thirdObservation := make(chan struct{})
	resumeObservation := make(chan struct{})
	observationCount := 0
	store.queryObserver = func(kind sqliteQueryKind) {
		if kind != sqliteQueryWaitObservation {
			return
		}
		observationCount++
		if observationCount == 3 {
			close(thirdObservation)
			<-resumeObservation
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	waitResult := make(chan error, 1)
	go func() { waitResult <- store.Wait(waitCtx, streamID) }()
	<-thirdObservation

	if _, err := store.MarkPluginTransition(ctx, PluginTransitionRequest{
		PluginInstanceID: pluginInstanceID,
		Status:           StatusOrphanedRemoved,
		Reason:           "plugin removed",
	}); err != nil {
		close(resumeObservation)
		t.Fatal(err)
	}
	close(resumeObservation)

	if err := <-waitResult; err != nil {
		t.Fatalf("Wait() lost the concurrent plugin transition: %v", err)
	}
}

func TestSQLiteStorePluginTransitionDoesNotWakeUnrelatedWaiter(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	for streamID, pluginInstanceID := range map[string]string{
		"stream_waiting_plugin": "plugini_waiting",
		"stream_other_plugin":   "plugini_other",
	} {
		if _, err := store.Register(ctx, RegisterRequest{
			StreamID:         streamID,
			ExecutionBinding: streamTestBinding(pluginInstanceID),
		}); err != nil {
			t.Fatal(err)
		}
	}

	observed := make(chan struct{})
	observationCount := 0
	store.queryObserver = func(kind sqliteQueryKind) {
		if kind == sqliteQueryWaitObservation {
			observationCount++
			if observationCount == 3 {
				close(observed)
			}
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- store.Wait(waitCtx, "stream_waiting_plugin") }()
	<-observed

	if _, err := store.MarkPluginTransition(ctx, PluginTransitionRequest{
		PluginInstanceID: "plugini_other",
		Status:           StatusOrphanedDisabled,
		Reason:           "plugin disabled",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		t.Fatalf("unrelated plugin transition woke waiter: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_waiting_plugin", Data: []byte("ready")}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("Wait() after matching stream event: %v", err)
	}
}

func TestSQLiteStoreCloseWakesWaitersAndRejectsNewWaits(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         "stream_store_close",
		ExecutionBinding: streamTestBinding("plugini_store_close"),
	}); err != nil {
		t.Fatal(err)
	}
	observed := make(chan struct{})
	releaseObservation := make(chan struct{})
	observationCount := 0
	store.queryObserver = func(kind sqliteQueryKind) {
		if kind == sqliteQueryWaitObservation {
			observationCount++
			if observationCount == 3 {
				close(observed)
				<-releaseObservation
			}
		}
	}
	_, transitionReady, err := store.transitionSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- store.Wait(context.Background(), "stream_store_close") }()
	<-observed
	closeResult := make(chan error, 1)
	go func() { closeResult <- store.CloseDatabase() }()
	<-transitionReady
	close(releaseObservation)
	if err := <-result; err != nil {
		t.Fatalf("parked Wait() after store close: %v", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
	if err := store.Wait(context.Background(), "stream_store_close"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("new Wait() after store close = %v, want %v", err, ErrStoreClosed)
	}
}

func TestSQLiteStoreAcknowledgeRejectsBufferedByteUnderflow(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseDatabase() })
	const streamID = "stream_buffered_byte_invariant"
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         streamID,
		ExecutionBinding: streamTestBinding("plugini_buffered_byte_invariant"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(ctx, AppendRequest{StreamID: streamID, Data: []byte("payload")}); err != nil {
		t.Fatal(err)
	}
	_, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: streamID, ReadID: "read_invariant_0001"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE plugin_streams SET buffered_bytes = 0 WHERE stream_id = ?`, streamID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: streamID, DeliveryID: delivery.DeliveryID}); !errors.Is(err, ErrStreamInvariant) {
		t.Fatalf("Acknowledge() error = %v, want %v", err, ErrStreamInvariant)
	}
	var eventCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_stream_events WHERE stream_id = ?`, streamID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("event count after rejected acknowledgement = %d, want 1", eventCount)
	}
}

func TestStoresChargeEmptyAndErrorEventsAgainstBackpressure(t *testing.T) {
	tests := []struct {
		name string
		open func(t *testing.T) Store
	}{
		{name: "memory", open: func(t *testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "streams.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.CloseDatabase() })
			return store
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := test.open(t)
			emptyCost := streamEventCost(Event{Kind: "data"})
			if _, err := store.Register(context.Background(), RegisterRequest{
				StreamID:         "stream_empty",
				ExecutionBinding: streamTestBinding("plugini_empty"),
				MaxBufferedBytes: 2 * emptyCost,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_empty"}); err != nil {
				t.Fatalf("Append(first empty event) error = %v", err)
			}
			if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_empty"}); err != nil {
				t.Fatalf("Append(second empty event) error = %v", err)
			}
			if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_empty"}); !errors.Is(err, ErrBackpressure) {
				t.Fatalf("Append(third empty event) error = %v, want ErrBackpressure", err)
			}
			record, delivery, err := store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_empty", ReadID: "read_empty_test_1", MaxBytes: emptyCost})
			if err != nil || len(delivery.Events) != 1 || record.BufferedBytes != 2*emptyCost {
				t.Fatalf("Deliver(empty event) record=%#v delivery=%#v err=%v", record, delivery, err)
			}
			record, err = store.Acknowledge(context.Background(), AcknowledgeRequest{StreamID: "stream_empty", DeliveryID: delivery.DeliveryID})
			if err != nil || record.BufferedBytes != emptyCost {
				t.Fatalf("Acknowledge(empty event) record=%#v err=%v", record, err)
			}
			record, delivery, err = store.Deliver(context.Background(), DeliverRequest{StreamID: "stream_empty", ReadID: "read_empty_test_2", MaxBytes: emptyCost})
			if err != nil || len(delivery.Events) != 1 || record.BufferedBytes != emptyCost {
				t.Fatalf("Deliver(second empty event) record=%#v delivery=%#v err=%v", record, delivery, err)
			}
			record, err = store.Acknowledge(context.Background(), AcknowledgeRequest{StreamID: "stream_empty", DeliveryID: delivery.DeliveryID})
			if err != nil || record.BufferedBytes != 0 {
				t.Fatalf("Acknowledge(second empty event) record=%#v err=%v", record, err)
			}

			largeError := strings.Repeat("x", 256)
			if _, err := store.Register(context.Background(), RegisterRequest{
				StreamID:         "stream_error",
				ExecutionBinding: streamTestBinding("plugini_error"),
				MaxBufferedBytes: streamEventCost(Event{Kind: "error", Error: largeError}) - 1,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Append(context.Background(), AppendRequest{StreamID: "stream_error", Kind: "error", Error: largeError}); !errors.Is(err, ErrBackpressure) {
				t.Fatalf("Append(large error) error = %v, want ErrBackpressure", err)
			}
		})
	}
}

func TestSQLiteStoreBoundsBacklogReadsAndKeepsRowSequence(t *testing.T) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "streams.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.CloseDatabase(); err != nil {
			t.Errorf("CloseDatabase() error = %v", err)
		}
	})
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         "stream_bounded",
		ExecutionBinding: streamTestBinding("plugini_bounded"),
		MaxBufferedBytes: int64(maxSQLiteReadEvents+5) * streamEventCost(Event{Kind: "data", Data: []byte("x")}),
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxSQLiteReadEvents+5; index++ {
		if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_bounded", Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	_, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: "stream_bounded", ReadID: "read_bounded_1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Events) != maxSQLiteReadEvents || delivery.Events[0].Sequence != 1 || delivery.Events[len(delivery.Events)-1].Sequence != maxSQLiteReadEvents {
		t.Fatalf("bounded events mismatch: len=%d first=%d last=%d", len(delivery.Events), delivery.Events[0].Sequence, delivery.Events[len(delivery.Events)-1].Sequence)
	}
	if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_bounded", DeliveryID: delivery.DeliveryID}); err != nil {
		t.Fatal(err)
	}
	event, err := store.Append(ctx, AppendRequest{StreamID: "stream_bounded", Data: []byte("y")})
	if err != nil {
		t.Fatal(err)
	}
	if event.Sequence != maxSQLiteReadEvents+6 {
		t.Fatalf("sequence = %d, want %d", event.Sequence, maxSQLiteReadEvents+6)
	}
}

func BenchmarkSQLiteStoreBoundedRead(b *testing.B) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(b.TempDir(), "streams.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := store.CloseDatabase(); err != nil {
			b.Errorf("CloseDatabase() error = %v", err)
		}
	})
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         "stream_bench",
		ExecutionBinding: streamTestBinding("plugini_bench"),
		MaxBufferedBytes: 1 << 30,
	}); err != nil {
		b.Fatal(err)
	}
	for index := 0; index < maxSQLiteReadEvents; index++ {
		if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_bench", Data: []byte("x")}); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_, delivery, err := store.Deliver(ctx, DeliverRequest{StreamID: "stream_bench", ReadID: fmt.Sprintf("read_bench_%08d", index), MaxEvents: 1})
		if err != nil || len(delivery.Events) != 1 {
			b.Fatalf("Deliver() events=%d err=%v", len(delivery.Events), err)
		}
		if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_bench", DeliveryID: delivery.DeliveryID}); err != nil {
			b.Fatal(err)
		}
		if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_bench", Data: []byte("x")}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSQLiteStoreBatchAcknowledge(b *testing.B) {
	ctx := context.Background()
	store, err := NewSQLiteStore(ctx, filepath.Join(b.TempDir(), "streams.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := store.CloseDatabase(); err != nil {
			b.Errorf("CloseDatabase() error = %v", err)
		}
	})
	const eventCount = 1000
	payload := make([]byte, 1024)
	eventCost := streamEventCost(Event{Kind: "data", Data: payload})
	if _, err := store.Register(ctx, RegisterRequest{
		StreamID:         "stream_batch_ack_bench",
		ExecutionBinding: streamTestBinding("plugini_batch_ack_bench"),
		MaxBufferedBytes: int64(eventCount) * eventCost,
	}); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(eventCount), "events/ack")
	b.ReportMetric(float64(len(payload)), "bytes/event")
	for index := 0; index < b.N; index++ {
		b.StopTimer()
		for eventIndex := 0; eventIndex < eventCount; eventIndex++ {
			if _, err := store.Append(ctx, AppendRequest{StreamID: "stream_batch_ack_bench", Data: payload}); err != nil {
				b.Fatal(err)
			}
		}
		_, delivery, err := store.Deliver(ctx, DeliverRequest{
			StreamID:  "stream_batch_ack_bench",
			ReadID:    fmt.Sprintf("read_batch_ack_%08d", index),
			MaxEvents: eventCount,
		})
		if err != nil || len(delivery.Events) != eventCount {
			b.Fatalf("Deliver() events=%d err=%v", len(delivery.Events), err)
		}
		b.StartTimer()
		if _, err := store.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_batch_ack_bench", DeliveryID: delivery.DeliveryID}); err != nil {
			b.Fatal(err)
		}
	}
}

func forEachStreamStore(t *testing.T, run func(t *testing.T, store Store)) {
	t.Helper()
	tests := []struct {
		name string
		open func(t *testing.T) Store
	}{
		{name: "memory", open: func(t *testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "streams.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.CloseDatabase() })
			return store
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run(t, test.open(t))
		})
	}
}

func waitForNotificationState(t *testing.T, store Store, streamID string, wantEntries, wantWaiters int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		entries, waiters := notificationState(store, streamID)
		if entries == wantEntries && waiters == wantWaiters {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("notification state = entries:%d waiters:%d, want entries:%d waiters:%d", entries, waiters, wantEntries, wantWaiters)
		}
		time.Sleep(time.Millisecond)
	}
}

func notificationState(store Store, streamID string) (int, int) {
	switch typed := store.(type) {
	case *MemoryStore:
		typed.mu.Lock()
		defer typed.mu.Unlock()
		notification := typed.notify[streamID]
		if notification == nil {
			return len(typed.notify), 0
		}
		return len(typed.notify), notification.waiters
	case *SQLiteStore:
		typed.notifyMu.Lock()
		defer typed.notifyMu.Unlock()
		notification := typed.notify[streamID]
		if notification == nil {
			return len(typed.notify), 0
		}
		return len(typed.notify), notification.waiters
	default:
		panic(fmt.Sprintf("unexpected stream store %T", store))
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
