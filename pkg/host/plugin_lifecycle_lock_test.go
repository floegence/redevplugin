package host

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPluginLifecycleLockRegistryAllowsIndependentPlugins(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseA, err := registry.acquireWrite(context.Background(), "plugin_a")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	acquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireWrite(context.Background(), "plugin_b")
		if acquireErr != nil {
			close(acquired)
			return
		}
		acquired <- release
	}()
	select {
	case release, ok := <-acquired:
		if !ok {
			t.Fatal("acquireWrite(plugin_b) failed")
		}
		release()
	case <-time.After(100 * time.Millisecond):
		t.Fatal("independent plugin lock was blocked")
	}
}

func TestPluginLifecycleLockRegistrySerializesSamePlugin(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseWrite, err := registry.acquireWrite(context.Background(), "plugin_a")
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireRead(context.Background(), "plugin_a")
		if acquireErr != nil {
			close(acquired)
			return
		}
		acquired <- release
	}()
	select {
	case <-acquired:
		t.Fatal("same-plugin read lock acquired while write lock was held")
	case <-time.After(20 * time.Millisecond):
	}
	releaseWrite()
	select {
	case release, ok := <-acquired:
		if !ok {
			t.Fatal("acquireRead(plugin_a) failed")
		}
		release()
	case <-time.After(100 * time.Millisecond):
		t.Fatal("same-plugin read lock did not acquire after write release")
	}
}

func TestPluginLifecycleLockRegistryOrdersMultiPluginWrites(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseFirst, err := registry.acquireWriteMany(context.Background(), "plugin_b", "plugin_a")
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireWriteMany(context.Background(), "plugin_a", "plugin_b")
		if acquireErr != nil {
			close(acquired)
			return
		}
		acquired <- release
	}()
	select {
	case <-acquired:
		t.Fatal("overlapping multi-plugin write lock acquired before release")
	case <-time.After(20 * time.Millisecond):
	}
	releaseFirst()
	select {
	case release, ok := <-acquired:
		if !ok {
			t.Fatal("acquireWriteMany() failed")
		}
		release()
	case <-time.After(100 * time.Millisecond):
		t.Fatal("multi-plugin write lock did not acquire after release")
	}
}

func TestPluginLifecycleLockRegistryCanceledWaitersAreRemoved(t *testing.T) {
	for _, mode := range []string{"read", "write"} {
		t.Run(mode, func(t *testing.T) {
			registry := newPluginLifecycleLockRegistry()
			releaseHeld, err := registry.acquireWrite(context.Background(), "plugin_a")
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				var acquireErr error
				if mode == "read" {
					_, acquireErr = registry.acquireRead(ctx, "plugin_a")
				} else {
					_, acquireErr = registry.acquireWrite(ctx, "plugin_a")
				}
				result <- acquireErr
			}()
			waitForLifecycleWaiters(t, registry, 1)
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled %s waiter error = %v, want %v", mode, err, context.Canceled)
			}
			waitForLifecycleWaiters(t, registry, 0)
			releaseHeld()
			waitForLifecycleEntries(t, registry, 0)
		})
	}
}

func TestPluginLifecycleLockRegistryMultiWriteWaitsWithoutHoldingPartialKeys(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseB, err := registry.acquireWrite(context.Background(), "plugin_b")
	if err != nil {
		t.Fatal(err)
	}

	multiCtx, cancelMulti := context.WithCancel(context.Background())
	multiResult := make(chan error, 1)
	go func() {
		_, acquireErr := registry.acquireWriteMany(multiCtx, "plugin_a", "plugin_b")
		multiResult <- acquireErr
	}()
	waitForLifecycleWaiters(t, registry, 1)

	registry.mu.Lock()
	_, partialKeyHeld := registry.entries["plugin_a"]
	registry.mu.Unlock()
	if partialKeyHeld {
		t.Fatal("waiting multi-write held plugin_a before plugin_b became available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releaseC, err := registry.acquireWrite(ctx, "plugin_c")
	if err != nil {
		t.Fatalf("independent acquisition while multi-write waited: %v", err)
	}
	releaseC()

	cancelMulti()
	if err := <-multiResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled multi-write error = %v, want %v", err, context.Canceled)
	}
	releaseB()
	waitForLifecycleEntries(t, registry, 0)
}

func TestPluginLifecycleLockRegistryQueuedWriterPrecedesNewReaders(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseInitialRead, err := registry.acquireRead(context.Background(), "plugin_a")
	if err != nil {
		t.Fatal(err)
	}

	writerAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireWrite(context.Background(), "plugin_a")
		if acquireErr == nil {
			writerAcquired <- release
		}
	}()
	waitForLifecycleWaiters(t, registry, 1)

	readerAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireRead(context.Background(), "plugin_a")
		if acquireErr == nil {
			readerAcquired <- release
		}
	}()
	waitForLifecycleWaiters(t, registry, 2)
	releaseInitialRead()

	var releaseWriter func()
	select {
	case releaseWriter = <-writerAcquired:
	case <-readerAcquired:
		t.Fatal("new reader bypassed a queued writer")
	case <-time.After(time.Second):
		t.Fatal("queued writer did not acquire after readers released")
	}
	select {
	case <-readerAcquired:
		t.Fatal("new reader acquired while writer held the key")
	case <-time.After(20 * time.Millisecond):
	}
	releaseWriter()
	select {
	case releaseReader := <-readerAcquired:
		releaseReader()
	case <-time.After(time.Second):
		t.Fatal("reader did not acquire after queued writer released")
	}
	waitForLifecycleEntries(t, registry, 0)
}

func TestPluginLifecycleLockRegistryQueuedMultiWriterPrecedesNewReaders(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseA, err := registry.acquireRead(context.Background(), "plugin_a")
	if err != nil {
		t.Fatal(err)
	}
	releaseB, err := registry.acquireWrite(context.Background(), "plugin_b")
	if err != nil {
		t.Fatal(err)
	}

	writerAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireWriteMany(context.Background(), "plugin_a", "plugin_b")
		if acquireErr == nil {
			writerAcquired <- release
		}
	}()
	waitForLifecycleWaiters(t, registry, 1)

	readerAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireRead(context.Background(), "plugin_a")
		if acquireErr == nil {
			readerAcquired <- release
		}
	}()
	waitForLifecycleWaiters(t, registry, 2)
	releaseB()
	select {
	case <-readerAcquired:
		t.Fatal("new reader bypassed a queued multi-key writer")
	case <-time.After(20 * time.Millisecond):
	}
	releaseA()

	var releaseWriter func()
	select {
	case releaseWriter = <-writerAcquired:
	case <-readerAcquired:
		t.Fatal("new reader acquired before queued multi-key writer")
	case <-time.After(time.Second):
		t.Fatal("queued multi-key writer did not acquire after blockers released")
	}
	releaseWriter()
	select {
	case releaseReader := <-readerAcquired:
		releaseReader()
	case <-time.After(time.Second):
		t.Fatal("reader did not acquire after multi-key writer released")
	}
	waitForLifecycleEntries(t, registry, 0)
}

func waitForLifecycleWaiters(t *testing.T, registry *pluginLifecycleLockRegistry, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		got := len(registry.waiters)
		registry.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lifecycle waiter count did not reach %d", want)
}

func waitForLifecycleEntries(t *testing.T, registry *pluginLifecycleLockRegistry, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		got := len(registry.entries)
		registry.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lifecycle entry count did not reach %d", want)
}
