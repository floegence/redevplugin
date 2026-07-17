package host

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/stream"
)

func TestExecutionLeaseRegistryValidatesDifferentPluginsConcurrently(t *testing.T) {
	registry := newExecutionLeaseRegistry()
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstResult := make(chan *executionLease, 1)
	firstError := make(chan error, 1)
	go func() {
		lease, err := registry.start(context.Background(), executionRegistryTestBinding("invoke-a", "plugin-a", 0), func(context.Context) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
		firstResult <- lease
		firstError <- err
	}()
	<-firstEntered

	secondDone := make(chan struct{})
	var secondLease *executionLease
	var secondErr error
	go func() {
		secondLease, secondErr = registry.start(context.Background(), executionRegistryTestBinding("invoke-b", "plugin-b", 0), func(context.Context) error {
			return nil
		})
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("different plugin validation was blocked by the registry-wide lock")
	}
	if secondErr != nil {
		t.Fatalf("second start error = %v", secondErr)
	}
	if secondLease == nil || !secondLease.finish() {
		t.Fatal("second lease was not created and finished")
	}

	close(releaseFirst)
	firstLease := <-firstResult
	if err := <-firstError; err != nil {
		t.Fatalf("first start error = %v", err)
	}
	if firstLease == nil || !firstLease.finish() {
		t.Fatal("first lease was not created and finished")
	}
}

func TestExecutionLeaseRegistryPluginRevokeFencesConcurrentStart(t *testing.T) {
	registry := newExecutionLeaseRegistry()
	validationEntered := make(chan struct{})
	releaseValidation := make(chan struct{})
	startResult := make(chan *executionLease, 1)
	startError := make(chan error, 1)
	go func() {
		lease, err := registry.start(context.Background(), executionRegistryTestBinding("invoke-a", "plugin-a", 0), func(context.Context) error {
			close(validationEntered)
			<-releaseValidation
			return nil
		})
		startResult <- lease
		startError <- err
	}()
	<-validationEntered

	revokedResult := make(chan []*executionLease, 1)
	go func() {
		revokedResult <- registry.cancelPlugin("plugin-a", capability.ErrExecutionRevoked)
	}()
	select {
	case <-revokedResult:
		t.Fatal("plugin revoke passed an in-flight validation without fencing its lease")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseValidation)
	lease := <-startResult
	if err := <-startError; err != nil {
		t.Fatalf("start error = %v", err)
	}
	revoked := <-revokedResult
	if len(revoked) != 1 || revoked[0] != lease {
		t.Fatalf("revoked leases = %#v, want the concurrently started lease", revoked)
	}
	if err := lease.validate(context.Background()); !errors.Is(err, capability.ErrExecutionRevoked) {
		t.Fatalf("lease validate error = %v, want ErrExecutionRevoked", err)
	}
	lease.finish()
}

func TestExecutionLeaseRegistryMaintainsQuotaAndIdentityIndexes(t *testing.T) {
	registry := newExecutionLeaseRegistry()
	binding := executionRegistryTestBinding("invoke-a", "plugin-a", 1)
	lease, err := registry.start(context.Background(), binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("start first lease: %v", err)
	}

	blocked := binding
	blocked.InvocationID = "invoke-b"
	if _, err := registry.start(context.Background(), blocked, func(context.Context) error { return nil }); !errors.Is(err, capability.ErrQuotaExceeded) {
		t.Fatalf("second start error = %v, want ErrQuotaExceeded", err)
	}

	operationSink := &hostOperationSink{lease: lease, operationID: "operation-indexed"}
	streamSink := &hostStreamSink{lease: lease, streamID: "stream-indexed"}
	lease.setOperation(operationSink, nil)
	lease.setStream(streamSink)
	if !registry.hasOperation(operationSink.operationID) {
		t.Fatal("operation index does not contain the live lease")
	}
	gotStream, err := registry.streamSink(streamSink.streamID)
	if err != nil || gotStream != streamSink {
		t.Fatalf("stream index result = (%p, %v), want (%p, nil)", gotStream, err, streamSink)
	}

	if !lease.finish() {
		t.Fatal("first lease did not finish")
	}
	if registry.hasOperation(operationSink.operationID) {
		t.Fatal("operation index retained a finished lease")
	}
	if _, err := registry.streamSink(streamSink.streamID); !errors.Is(err, stream.ErrNotFound) {
		t.Fatalf("finished stream lookup error = %v, want ErrNotFound", err)
	}

	replacement := binding
	replacement.InvocationID = "invoke-c"
	replacementLease, err := registry.start(context.Background(), replacement, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("start replacement lease after quota release: %v", err)
	}
	replacementLease.finish()

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.leases) != 0 || len(registry.leasesByPlugin) != 0 || len(registry.operations) != 0 ||
		len(registry.streams) != 0 || len(registry.activeByQuotaKey) != 0 || len(registry.setupRollbacks) != 0 || len(registry.pluginGates) != 0 {
		t.Fatalf("finished registry retained indexes: %#v", registry)
	}
}

func BenchmarkExecutionLeaseRegistryIndexedStreamLookup(b *testing.B) {
	registry := newExecutionLeaseRegistry()
	leases := make([]*executionLease, 0, 10_000)
	for index := 0; index < cap(leases); index++ {
		lease, err := registry.start(
			context.Background(),
			executionRegistryTestBinding(fmt.Sprintf("invoke-%d", index), fmt.Sprintf("plugin-%d", index), 0),
			func(context.Context) error { return nil },
		)
		if err != nil {
			b.Fatal(err)
		}
		lease.setStream(&hostStreamSink{lease: lease, streamID: fmt.Sprintf("stream-%d", index)})
		leases = append(leases, lease)
	}
	target := "stream-9999"
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := registry.streamSink(target); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	for _, lease := range leases {
		lease.finish()
	}
}

func BenchmarkExecutionLeaseRegistrySuppressedTerminalMaintenance(b *testing.B) {
	registry := newExecutionLeaseRegistry()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if !registry.beginTerminalMaintenance(now) {
		b.Fatal("initial terminal maintenance was not admitted")
	}
	registry.finishTerminalMaintenance()
	b.ResetTimer()
	for range b.N {
		if registry.beginTerminalMaintenance(now) {
			b.Fatal("terminal maintenance was admitted inside the fixed interval")
		}
	}
}

func BenchmarkExecutionLeaseRegistryPendingSetupRollbackLookup(b *testing.B) {
	registry := newExecutionLeaseRegistry()
	leases := make([]*executionLease, 0, 10_000)
	for index := 0; index < cap(leases); index++ {
		lease, err := registry.start(
			context.Background(),
			executionRegistryTestBinding(fmt.Sprintf("invoke-%d", index), fmt.Sprintf("plugin-%d", index), 0),
			func(context.Context) error { return nil },
		)
		if err != nil {
			b.Fatal(err)
		}
		leases = append(leases, lease)
	}
	leases[len(leases)-1].markSetupRollbackPending(errors.New("terminal store unavailable"))
	b.ResetTimer()
	for range b.N {
		if pending := registry.pendingSetupRollbacks("plugin-9999"); len(pending) != 1 {
			b.Fatalf("pending setup rollbacks = %d, want 1", len(pending))
		}
	}
	b.StopTimer()
	for _, lease := range leases {
		lease.finish()
	}
}

func executionRegistryTestBinding(invocationID string, pluginInstanceID string, maxConcurrent int) capability.ExecutionBinding {
	return capability.ExecutionBinding{
		InvocationID:     invocationID,
		PluginInstanceID: pluginInstanceID,
		CapabilityID:     "test.capability",
		Method:           "test.run",
		Execution:        "sync",
		Quota: capability.QuotaGrant{
			MaxConcurrent: maxConcurrent,
		},
	}
}
