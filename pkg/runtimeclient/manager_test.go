package runtimeclient

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessManagerStartsEveryShardAndBindsDeterministically(t *testing.T) {
	shards := []*fakeProcessShard{
		{health: testShardHealth("a")},
		{health: testShardHealth("b")},
		{health: testShardHealth("c")},
	}
	manager := testProcessManager(t, shards)
	health, err := manager.Start(context.Background(), Target{OS: "test", Arch: "test"})
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
	if _, err := manager.Start(context.Background(), Target{}); !errors.Is(err, startFailure) {
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
	_, err := manager.Start(context.Background(), Target{})
	if !errors.Is(err, startFailure) || !errors.Is(err, rollbackFailure) || !errors.Is(err, ErrManagerLifecycleOutcomeUnknown) {
		t.Fatalf("Start() error = %v, want start, rollback, and unknown outcome errors", err)
	}
}

func TestProcessManagerDoesNotRemapFailedShard(t *testing.T) {
	shards := []*fakeProcessShard{
		{health: testShardHealth("a")},
		{health: testShardHealth("b")},
	}
	manager := testProcessManager(t, shards)
	if _, err := manager.Start(context.Background(), Target{}); err != nil {
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
	if _, err := manager.Start(context.Background(), Target{}); err != nil {
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
	if _, err := manager.Start(context.Background(), Target{}); err != nil {
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
	if _, err := manager.Start(context.Background(), Target{}); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Revoke(context.Background(), "plugini_1", 4)
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
	if _, err := manager.Start(context.Background(), Target{}); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Revoke(context.Background(), "plugini_1", 4)
	if !errors.Is(err, revokeFailure) || !errors.Is(err, stopFailure) {
		t.Fatalf("Revoke() error = %v, want revoke and termination failures", err)
	}
}

func testProcessManager(t *testing.T, shards []*fakeProcessShard) *ProcessManager {
	t.Helper()
	next := 0
	manager, err := newProcessManager(ProcessManagerOptions{ShardCount: len(shards)}, func(ProcessSupervisorOptions) (processShard, error) {
		shard := shards[next]
		next++
		return shard, nil
	})
	if err != nil {
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
	mu          sync.Mutex
	health      Health
	startErr    error
	stopErr     error
	revokeErr   error
	invoke      func(context.Context) ([]byte, error)
	stop        func()
	startCalls  atomic.Int64
	stopCalls   atomic.Int64
	invokeCalls atomic.Int64
	revokeCalls atomic.Int64
}

func (s *fakeProcessShard) Start(context.Context, Target) error {
	s.startCalls.Add(1)
	if s.startErr != nil {
		return s.startErr
	}
	s.mu.Lock()
	s.health.Ready = true
	s.mu.Unlock()
	return nil
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

func (s *fakeProcessShard) Revoke(context.Context, string, uint64) (RevokeResult, error) {
	s.revokeCalls.Add(1)
	return RevokeResult{}, s.revokeErr
}
