package runtimeclient

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

func TestProcessManagerStartsEveryShardAndBindsDeterministically(t *testing.T) {
	shards := []*fakeProcessShard{
		{health: testShardHealth("a")},
		{health: testShardHealth("b")},
		{health: testShardHealth("c")},
	}
	manager := testProcessManager(t, shards)
	health, err := manager.Start(context.Background(), testRuntimeTarget)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !health.Ready || len(health.Shards) != len(shards) {
		t.Fatalf("Start() health = %#v", health)
	}
	for index, shard := range shards {
		if shard.startCalls.Load() != 1 {
			t.Fatalf("shard %d start calls = %d, want 1", index, shard.startCalls.Load())
		}
	}

	for _, pluginInstanceID := range []string{"plugini_alpha", "plugini_beta", "plugini_gamma"} {
		first, err := manager.BindPlugin(context.Background(), pluginInstanceID)
		if err != nil {
			t.Fatalf("BindPlugin(%q) error = %v", pluginInstanceID, err)
		}
		second, err := manager.BindPlugin(context.Background(), pluginInstanceID)
		if err != nil {
			t.Fatalf("BindPlugin(%q second) error = %v", pluginInstanceID, err)
		}
		if first != second {
			t.Fatalf("BindPlugin(%q) changed binding: %#v != %#v", pluginInstanceID, first, second)
		}
		wantIndex := processShardIndex(pluginInstanceID, len(shards))
		if first.RuntimeGenerationID != shards[wantIndex].health.RuntimeGenerationID {
			t.Fatalf("BindPlugin(%q) generation = %q, want shard %d", pluginInstanceID, first.RuntimeGenerationID, wantIndex)
		}
	}
}

func TestProcessManagerStartRollsBackStartedShards(t *testing.T) {
	startFailure := errors.New("start failed")
	shards := []*fakeProcessShard{
		{health: testShardHealth("a")},
		{health: testShardHealth("b"), startErr: startFailure},
		{health: testShardHealth("c")},
	}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); !errors.Is(err, startFailure) {
		t.Fatalf("Start() error = %v, want %v", err, startFailure)
	}
	if shards[0].stopCalls.Load() != 1 {
		t.Fatalf("first shard stop calls = %d, want rollback", shards[0].stopCalls.Load())
	}
	if shards[2].startCalls.Load() != 0 {
		t.Fatalf("third shard start calls = %d, want 0", shards[2].startCalls.Load())
	}
	health, err := manager.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("manager health after rollback = %#v, want not ready", health)
	}
}

func TestProcessManagerStartReportsUnknownWhenRollbackFails(t *testing.T) {
	startFailure := errors.New("start failed")
	rollbackFailure := errors.New("rollback failed")
	shards := []*fakeProcessShard{
		{health: testShardHealth("a"), stopErr: rollbackFailure},
		{health: testShardHealth("b"), startErr: startFailure},
	}
	manager := testProcessManager(t, shards)
	_, err := manager.Start(context.Background(), testRuntimeTarget)
	if !errors.Is(err, startFailure) || !errors.Is(err, rollbackFailure) || !errors.Is(err, ErrManagerLifecycleOutcomeUnknown) {
		t.Fatalf("Start() error = %v, want start, rollback, and unknown outcome errors", err)
	}
}

func TestProcessManagerPreflightRejectsShardDescriptorDrift(t *testing.T) {
	first := testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64))
	second := testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("b", 64))
	manager := testProcessManager(t, []*fakeProcessShard{
		{health: testShardHealth("a"), descriptor: first},
		{health: testShardHealth("b"), descriptor: second},
	})

	if _, err := manager.Preflight(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeDescriptorMismatch) {
		t.Fatalf("Preflight() error = %v, want ErrRuntimeDescriptorMismatch", err)
	}
}

func TestProcessManagerPreflightRejectsDescriptorForDifferentTarget(t *testing.T) {
	wrongTarget := runtimetarget.LinuxAMD64
	manager := testProcessManager(t, []*fakeProcessShard{{
		health:     testShardHealth("a"),
		descriptor: testRuntimeDescriptor(wrongTarget, strings.Repeat("a", 64)),
	}})

	if _, err := manager.Preflight(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeDescriptorMismatch) {
		t.Fatalf("Preflight() error = %v, want ErrRuntimeDescriptorMismatch", err)
	}
}

func TestProcessManagerStartRejectsReadyShardDescriptorMismatch(t *testing.T) {
	configured := testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64))
	running := testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("b", 64))
	shard := &fakeProcessShard{
		descriptor: configured,
		health: Health{
			RuntimeInstanceID:   "instance_a",
			RuntimeGenerationID: "generation_a",
			IPCChannelID:        "ipc_a",
			ConnectionNonce:     "nonce_a",
			Descriptor:          running,
			Ready:               true,
		},
	}
	manager := testProcessManager(t, []*fakeProcessShard{shard})

	if _, err := manager.Start(context.Background(), testRuntimeTarget); !errors.Is(err, ErrRuntimeDescriptorMismatch) {
		t.Fatalf("Start() error = %v, want ErrRuntimeDescriptorMismatch", err)
	}
	if shard.startCalls.Load() != 0 {
		t.Fatalf("Start() calls = %d, want zero for mismatched ready shard", shard.startCalls.Load())
	}
}

func TestProcessManagerDoesNotRemapFailedShard(t *testing.T) {
	shards := []*fakeProcessShard{
		{health: testShardHealth("a")},
		{health: testShardHealth("b")},
	}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	pluginInstanceID := pluginForShard(t, len(shards), 1)
	binding, err := manager.BindPlugin(context.Background(), pluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	shards[1].mu.Lock()
	shards[1].health.Ready = false
	shards[1].mu.Unlock()
	if _, err := manager.BindPlugin(context.Background(), pluginInstanceID); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("BindPlugin() error = %v, want ErrRuntimeNotReady", err)
	}
	lease := leaseForBinding(pluginInstanceID, binding)
	if _, err := manager.InvokeWorker(context.Background(), binding, lease, "worker.echo", nil); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeNotReady", err)
	}
	if shards[0].invokeCalls.Load() != 0 {
		t.Fatalf("healthy shard invoke calls = %d, plugin was remapped", shards[0].invokeCalls.Load())
	}
}

func TestProcessManagerRejectsStaleBindingAndLease(t *testing.T) {
	shards := []*fakeProcessShard{{health: testShardHealth("a")}}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.BindPlugin(context.Background(), "plugini_1")
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseForBinding("plugini_1", binding)
	shards[0].mu.Lock()
	shards[0].health.RuntimeGenerationID = "generation_restarted"
	shards[0].mu.Unlock()
	if _, err := manager.InvokeWorker(context.Background(), binding, lease, "worker.echo", nil); !errors.Is(err, ErrRuntimeBindingInvalid) {
		t.Fatalf("InvokeWorker(stale binding) error = %v, want ErrRuntimeBindingInvalid", err)
	}

	current, err := manager.BindPlugin(context.Background(), "plugini_1")
	if err != nil {
		t.Fatal(err)
	}
	lease = leaseForBinding("plugini_1", current)
	lease.ConnectionNonce = "wrong_nonce"
	if _, err := manager.InvokeWorker(context.Background(), current, lease, "worker.echo", nil); !errors.Is(err, ErrRuntimeBindingInvalid) {
		t.Fatalf("InvokeWorker(mismatched lease) error = %v, want ErrRuntimeBindingInvalid", err)
	}
}

func TestProcessManagerRejectsStaleBindingDescriptorBeforeDispatch(t *testing.T) {
	shard := &fakeProcessShard{health: testShardHealth("a")}
	manager := testProcessManager(t, []*fakeProcessShard{shard})
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.BindPlugin(context.Background(), "plugini_1")
	if err != nil {
		t.Fatal(err)
	}
	lease := leaseForBinding("plugini_1", binding)
	shard.mu.Lock()
	shard.health.Descriptor = testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("b", 64))
	shard.mu.Unlock()

	if _, err := manager.InvokeWorker(context.Background(), binding, lease, "worker.echo", nil); !errors.Is(err, ErrRuntimeBindingInvalid) {
		t.Fatalf("InvokeWorker() error = %v, want ErrRuntimeBindingInvalid", err)
	}
	if shard.invokeCalls.Load() != 0 {
		t.Fatalf("InvokeWorker() dispatch calls = %d, want zero", shard.invokeCalls.Load())
	}
}

func TestProcessManagerRoutesDifferentShardsWithoutGlobalBlocking(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	shards := []*fakeProcessShard{
		{health: testShardHealth("a"), invoke: func(context.Context) ([]byte, error) {
			close(slowStarted)
			<-releaseSlow
			return []byte("slow"), nil
		}},
		{health: testShardHealth("b"), invoke: func(context.Context) ([]byte, error) {
			return []byte("fast"), nil
		}},
	}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	slowPlugin := pluginForShard(t, len(shards), 0)
	fastPlugin := pluginForShard(t, len(shards), 1)
	slowBinding, err := manager.BindPlugin(context.Background(), slowPlugin)
	if err != nil {
		t.Fatal(err)
	}
	fastBinding, err := manager.BindPlugin(context.Background(), fastPlugin)
	if err != nil {
		t.Fatal(err)
	}
	slowDone := make(chan error, 1)
	go func() {
		_, err := manager.InvokeWorker(context.Background(), slowBinding, leaseForBinding(slowPlugin, slowBinding), "worker.echo", nil)
		slowDone <- err
	}()
	<-slowStarted

	fastCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := manager.InvokeWorker(fastCtx, fastBinding, leaseForBinding(fastPlugin, fastBinding), "worker.echo", nil)
	if err != nil {
		t.Fatalf("fast InvokeWorker() blocked behind another shard: %v", err)
	}
	if string(result) != "fast" {
		t.Fatalf("fast result = %q", result)
	}
	close(releaseSlow)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow InvokeWorker() error = %v", err)
	}
}

func TestProcessManagerStopsShardsConcurrently(t *testing.T) {
	stopEntered := make(chan struct{}, 2)
	releaseStop := make(chan struct{})
	shards := []*fakeProcessShard{
		{health: testShardHealth("a"), stop: func() { stopEntered <- struct{}{}; <-releaseStop }},
		{health: testShardHealth("b"), stop: func() { stopEntered <- struct{}{}; <-releaseStop }},
	}
	manager := testProcessManager(t, shards)
	done := make(chan error, 1)
	go func() { done <- manager.Stop(context.Background()) }()
	for range 2 {
		select {
		case <-stopEntered:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Stop() did not enter every shard concurrently")
		}
	}
	close(releaseStop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProcessManagerTerminatesOwningShardWhenRevokeFails(t *testing.T) {
	revokeFailure := errors.New("revoke acknowledgement lost")
	shards := []*fakeProcessShard{{health: testShardHealth("a"), revokeErr: revokeFailure}}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Revoke(context.Background(), testRevokeRequest("plugini_1", 4))
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if !result.RuntimeStopped || result.PluginInstanceID != "plugini_1" || result.RevokeEpoch != 4 {
		t.Fatalf("Revoke() result = %#v", result)
	}
	if shards[0].stopCalls.Load() != 1 {
		t.Fatalf("stop calls = %d, want 1", shards[0].stopCalls.Load())
	}
}

func TestProcessManagerReturnsRevokeAndTerminationFailures(t *testing.T) {
	revokeFailure := errors.New("revoke acknowledgement lost")
	stopFailure := errors.New("termination failed")
	shards := []*fakeProcessShard{{health: testShardHealth("a"), revokeErr: revokeFailure, stopErr: stopFailure}}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Revoke(context.Background(), testRevokeRequest("plugini_1", 4))
	if !errors.Is(err, revokeFailure) || !errors.Is(err, stopFailure) {
		t.Fatalf("Revoke() error = %v, want revoke and termination failures", err)
	}
}

func TestProcessManagerRejectsNonEnvironmentRevokeScopeBeforeShardAccess(t *testing.T) {
	shard := &fakeProcessShard{health: testShardHealth("a")}
	manager := testProcessManager(t, []*fakeProcessShard{shard})
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	req := testRevokeRequest("plugini_1", 4)
	req.ResourceScope = testUserResourceScope()
	_, err := manager.Revoke(context.Background(), req)
	if !errors.Is(err, ErrRuntimeRequestFailed) || !strings.Contains(err.Error(), "revoke resource scope must be an environment scope") {
		t.Fatalf("Revoke() error = %v, want typed environment scope validation failure", err)
	}
	if shard.revokeCalls.Load() != 0 || shard.stopCalls.Load() != 0 {
		t.Fatalf("invalid revoke reached shard: revoke=%d stop=%d", shard.revokeCalls.Load(), shard.stopCalls.Load())
	}
}

func TestProcessManagerRevokesSessionOnEveryShardAndAggregatesTerminalCounts(t *testing.T) {
	shards := []*fakeProcessShard{
		{health: testShardHealth("a"), sessionRevokeResult: SessionRevokeShardResult{
			RuntimeGenerationID: "generation_a", State: SessionRevokeStateComplete,
			Counts: SessionRevokeCounts{QueuedInvocations: 2, StorageHostcalls: 3},
		}},
		{health: testShardHealth("b"), sessionRevokeResult: SessionRevokeShardResult{
			RuntimeGenerationID: "generation_b", State: SessionRevokeStateComplete,
			Counts: SessionRevokeCounts{RunningInvocations: 5, Sockets: 7},
		}},
	}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	req := SessionRevokeRequest{SessionScope: testManagerSessionScope(), SessionRevokeSequence: 9}
	result, err := manager.RevokeSession(context.Background(), req)
	if err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if result.SessionScope != req.SessionScope || result.SessionRevokeSequence != req.SessionRevokeSequence || result.RuntimeStopped {
		t.Fatalf("RevokeSession() identity = %#v", result)
	}
	if len(result.Shards) != 2 || result.Shards[0].RuntimeShardID != "runtime_shard_00" || result.Shards[1].RuntimeShardID != "runtime_shard_01" {
		t.Fatalf("RevokeSession() shards = %#v", result.Shards)
	}
	if result.Counts != (SessionRevokeCounts{QueuedInvocations: 2, RunningInvocations: 5, StorageHostcalls: 3, Sockets: 7}) {
		t.Fatalf("RevokeSession() counts = %#v", result.Counts)
	}
	for index, shard := range shards {
		if shard.sessionRevokeCalls.Load() != 1 {
			t.Fatalf("shard %d session revoke calls = %d, want 1", index, shard.sessionRevokeCalls.Load())
		}
	}
}

func TestProcessManagerStopsEveryShardWhenSessionTerminalAckFails(t *testing.T) {
	revokeFailure := errors.New("terminal acknowledgement lost")
	shards := []*fakeProcessShard{
		{health: testShardHealth("a"), sessionRevokeResult: SessionRevokeShardResult{RuntimeGenerationID: "generation_a", State: SessionRevokeStateComplete}},
		{health: testShardHealth("b"), sessionRevokeErr: revokeFailure},
	}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	result, err := manager.RevokeSession(context.Background(), SessionRevokeRequest{
		SessionScope: testManagerSessionScope(), SessionRevokeSequence: 3,
	})
	if !errors.Is(err, revokeFailure) {
		t.Fatalf("RevokeSession() error = %v, want %v", err, revokeFailure)
	}
	if !result.RuntimeStopped {
		t.Fatalf("RevokeSession() result = %#v, want fail-closed runtime stop", result)
	}
	for index, shard := range shards {
		if shard.sessionRevokeCalls.Load() != 1 || shard.stopCalls.Load() != 1 {
			t.Fatalf("shard %d calls: revoke=%d stop=%d", index, shard.sessionRevokeCalls.Load(), shard.stopCalls.Load())
		}
	}
}

func TestProcessManagerSessionRevokeFailureRespectsCallerHardDeadline(t *testing.T) {
	revokeFailure := errors.New("terminal acknowledgement lost")
	releaseStop := make(chan struct{})
	shard := &fakeProcessShard{
		health: testShardHealth("a"), sessionRevokeErr: revokeFailure,
		stop: func() { <-releaseStop },
	}
	manager := testProcessManager(t, []*fakeProcessShard{shard})
	if _, err := manager.Start(context.Background(), testRuntimeTarget); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := manager.RevokeSession(ctx, SessionRevokeRequest{
		SessionScope: testManagerSessionScope(), SessionRevokeSequence: 4,
	})
	elapsed := time.Since(started)
	close(releaseStop)
	if !errors.Is(err, revokeFailure) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if result.RuntimeStopped {
		t.Fatalf("RevokeSession() result = %#v, stop did not acknowledge", result)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("RevokeSession() elapsed = %v, exceeded hard deadline allowance", elapsed)
	}
}

func TestProcessManagerRequiresExplicitShardCount(t *testing.T) {
	_, err := newProcessManager(ProcessManagerOptions{}, func(ProcessSupervisorOptions) (processShard, error) {
		return &fakeProcessShard{}, nil
	})
	if !errors.Is(err, ErrRuntimeShardCount) {
		t.Fatalf("newProcessManager() error = %v, want %v", err, ErrRuntimeShardCount)
	}
}

func TestProcessManagerBindsRequiredHostServicesBeforeCreatingShards(t *testing.T) {
	streamSink := &recordingRuntimeStreamSink{}
	var captured []ProcessSupervisorOptions
	manager, err := newProcessManager(ProcessManagerOptions{
		ShardCount: 2,
		Supervisor: ProcessSupervisorOptions{
			RuntimePath:           "redevplugin-runtime",
			Descriptor:            testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64)),
			Limits:                DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
		},
	}, func(options ProcessSupervisorOptions) (processShard, error) {
		captured = append(captured, options)
		return &fakeProcessShard{health: testShardHealth(string(rune('a' + len(captured) - 1)))}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 0 {
		t.Fatalf("runtime shards were created before host services binding: %d", len(captured))
	}
	if err := manager.BindHostServices(RuntimeHostServices{}); !errors.Is(err, ErrRuntimeHostServicesInvalid) {
		t.Fatalf("BindHostServices(empty) error = %v, want %v", err, ErrRuntimeHostServicesInvalid)
	}
	if err := manager.BindHostServices(RuntimeHostServices{StreamSink: streamSink}); err != nil {
		t.Fatalf("BindHostServices() error = %v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("created shards = %d, want 2", len(captured))
	}
	for index, options := range captured {
		if options.StreamSink != streamSink {
			t.Fatalf("shard %d stream sink = %#v, want exact host sink %#v", index, options.StreamSink, streamSink)
		}
	}
	if err := manager.BindHostServices(RuntimeHostServices{StreamSink: streamSink}); !errors.Is(err, ErrRuntimeHostServicesBound) {
		t.Fatalf("BindHostServices(second) error = %v, want %v", err, ErrRuntimeHostServicesBound)
	}
}

func TestProcessManagerRejectsTypedNilHostStreamSinkAndAllowsRetry(t *testing.T) {
	created := 0
	manager, err := newProcessManager(ProcessManagerOptions{
		ShardCount: 1,
		Supervisor: ProcessSupervisorOptions{
			RuntimePath:           "redevplugin-runtime",
			Descriptor:            testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64)),
			Limits:                DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
		},
	}, func(ProcessSupervisorOptions) (processShard, error) {
		created++
		return &fakeProcessShard{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *recordingRuntimeStreamSink
	if err := manager.BindHostServices(RuntimeHostServices{StreamSink: typedNil}); !errors.Is(err, ErrRuntimeHostServicesInvalid) {
		t.Fatalf("BindHostServices(typed nil) error = %v, want %v", err, ErrRuntimeHostServicesInvalid)
	}
	if created != 0 {
		t.Fatalf("typed-nil binding created %d shards, want 0", created)
	}
	if err := manager.BindHostServices(RuntimeHostServices{StreamSink: &recordingRuntimeStreamSink{}}); err != nil {
		t.Fatalf("BindHostServices() after rejected typed nil: %v", err)
	}
	if created != 1 {
		t.Fatalf("successful binding created %d shards, want 1", created)
	}
}

func testProcessManager(t *testing.T, shards []*fakeProcessShard) *ProcessManager {
	t.Helper()
	configuredDescriptor := testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64))
	for _, shard := range shards {
		if shard.descriptor.Version().String() == "" {
			shard.descriptor = configuredDescriptor
		}
		if shard.health.Descriptor.Version().String() == "" {
			shard.health.Descriptor = shard.descriptor
		}
	}
	next := 0
	manager, err := newProcessManager(ProcessManagerOptions{
		ShardCount: len(shards),
		Supervisor: ProcessSupervisorOptions{
			RuntimePath:           "redevplugin-runtime",
			Descriptor:            testRuntimeDescriptor(testRuntimeTarget, strings.Repeat("a", 64)),
			Limits:                DefaultRuntimeLimits(),
			HandshakeTimeout:      5 * time.Second,
			HeartbeatInterval:     2 * time.Second,
			MaxHeartbeatStaleness: 5 * time.Second,
		},
	}, func(ProcessSupervisorOptions) (processShard, error) {
		shard := shards[next]
		next++
		return shard, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BindHostServices(RuntimeHostServices{StreamSink: &recordingRuntimeStreamSink{}}); err != nil {
		t.Fatal(err)
	}
	return manager
}

func testShardHealth(id string) Health {
	return Health{
		RuntimeInstanceID:   "instance_" + id,
		RuntimeGenerationID: "generation_" + id,
		IPCChannelID:        "ipc_" + id,
		ConnectionNonce:     "nonce_" + id,
	}
}

func pluginForShard(t *testing.T, shardCount, want int) string {
	t.Helper()
	for index := 0; index < 10_000; index++ {
		candidate := "plugini_" + time.Unix(0, int64(index)).Format("150405.000000000")
		if processShardIndex(candidate, shardCount) == want {
			return candidate
		}
	}
	t.Fatalf("could not find plugin for shard %d", want)
	return ""
}

func leaseForBinding(pluginInstanceID string, binding RuntimeBinding) Lease {
	return Lease{
		PluginInstanceID:    pluginInstanceID,
		RuntimeShardID:      binding.RuntimeShardID,
		RuntimeInstanceID:   binding.RuntimeInstanceID,
		RuntimeGenerationID: binding.RuntimeGenerationID,
		IPCChannelID:        binding.IPCChannelID,
		ConnectionNonce:     binding.ConnectionNonce,
	}
}

type fakeProcessShard struct {
	mu                  sync.Mutex
	health              Health
	descriptor          RuntimeDescriptor
	preflightErr        error
	startErr            error
	stopErr             error
	revokeErr           error
	sessionRevokeErr    error
	sessionRevokeResult SessionRevokeShardResult
	invoke              func(context.Context) ([]byte, error)
	stop                func()
	startCalls          atomic.Int64
	stopCalls           atomic.Int64
	invokeCalls         atomic.Int64
	revokeCalls         atomic.Int64
	sessionRevokeCalls  atomic.Int64
}

type recordingRuntimeStreamSink struct{}

func (*recordingRuntimeStreamSink) AppendRuntimeStream(context.Context, string, string, []byte) error {
	return nil
}

func (*recordingRuntimeStreamSink) CloseRuntimeStream(context.Context, string) error {
	return nil
}

func (*recordingRuntimeStreamSink) FailRuntimeStream(context.Context, string, capability.ExecutionFailureCode, error) error {
	return nil
}

func (s *fakeProcessShard) Start(context.Context, runtimetarget.Target) error {
	s.startCalls.Add(1)
	if s.startErr != nil {
		return s.startErr
	}
	s.mu.Lock()
	s.health.Ready = true
	s.health.Descriptor = s.descriptor
	s.mu.Unlock()
	return nil
}

func (s *fakeProcessShard) Preflight(_ context.Context, target runtimetarget.Target) (RuntimeDescriptor, error) {
	if s.preflightErr != nil {
		return RuntimeDescriptor{}, s.preflightErr
	}
	descriptor := s.descriptor
	if descriptor.Version().String() == "" {
		descriptor = testRuntimeDescriptor(target, strings.Repeat("a", 64))
	}
	s.descriptor = descriptor
	return descriptor, nil
}

func (s *fakeProcessShard) Stop(context.Context) error {
	s.stopCalls.Add(1)
	if s.stop != nil {
		s.stop()
	}
	s.mu.Lock()
	s.health.Ready = false
	s.mu.Unlock()
	return s.stopErr
}

func (s *fakeProcessShard) Health(context.Context) (Health, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.health, nil
}

func (s *fakeProcessShard) InvokeWorker(ctx context.Context, _ Lease, _ string, _ []byte) ([]byte, error) {
	s.invokeCalls.Add(1)
	if s.invoke != nil {
		return s.invoke(ctx)
	}
	return []byte("ok"), nil
}

func (s *fakeProcessShard) Revoke(context.Context, RevokeRequest) (RevokeResult, error) {
	s.revokeCalls.Add(1)
	return RevokeResult{}, s.revokeErr
}

func (s *fakeProcessShard) RevokeSession(context.Context, SessionRevokeRequest) (SessionRevokeShardResult, error) {
	s.sessionRevokeCalls.Add(1)
	return s.sessionRevokeResult, s.sessionRevokeErr
}

func testManagerSessionScope() sessionctx.SessionScope {
	return sessionctx.SessionScope{
		OwnerSessionHash:     "session_hash",
		OwnerUserHash:        "user_hash",
		OwnerEnvHash:         "env_hash",
		SessionChannelIDHash: "channel_hash",
	}
}
