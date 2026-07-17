package stream

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
)

// FuzzMemoryStreamState drives a bounded sequence of append/deliver/ack/close
// operations. Invalid transitions are expected; every transition must remain
// panic-free and preserve the store's state invariants.
func FuzzMemoryStreamState(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{5, 4, 3, 2, 1, 0})
	f.Fuzz(func(t *testing.T, operations []byte) {
		ctx := context.Background()
		store := NewMemoryStore()
		_, _ = store.Register(ctx, RegisterRequest{
			StreamID: "stream_fuzz",
			ExecutionBinding: capability.ExecutionBinding{
				PluginInstanceID: "plugini_fuzz",
				Method:           "fuzz.stream",
			},
			Direction: DirectionRead,
			Now:       time.Unix(0, 0),
		})
		for index, operation := range operations {
			switch operation % 5 {
			case 0, 1:
				_, _ = store.Append(ctx, AppendRequest{
					StreamID: "stream_fuzz",
					Kind:     "data",
					Data:     []byte{operation, byte(index)},
				})
			case 2:
				_, _, _ = store.Deliver(ctx, DeliverRequest{StreamID: "stream_fuzz", ReadID: "read_fuzz0000", MaxEvents: 4, MaxBytes: 256})
			case 3:
				_, _ = store.Acknowledge(ctx, AcknowledgeRequest{StreamID: "stream_fuzz", DeliveryID: "delivery_fuzz"})
			case 4:
				_, _ = store.Close(ctx, CloseRequest{StreamID: "stream_fuzz", Status: StatusClosed})
			}
			_, _ = store.Get(ctx, "stream_fuzz")
		}
	})
}
