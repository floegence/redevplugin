package pluginpkg

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestWASMInspectionCacheHitReturnsOwnedContractClones(t *testing.T) {
	module := workerWASMWithTableForTest(1)
	var calls atomic.Int64
	cache := newWASMInspectionCache(wasmInspectionCacheCapacity, func(module []byte) (wasmModuleContract, error) {
		calls.Add(1)
		contract, err := inspectWASMModule(module)
		if err == nil {
			maximum := uint32(2)
			contract.TableLimits[0].Maximum = &maximum
		}
		return contract, err
	})
	first, err := cache.inspect(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	first.Types[0].Params[0] = 0
	first.FunctionTypeIndex[0] = 99
	delete(first.Exports, "memory")
	first.TableLimits[0].Initial = 99
	*first.TableLimits[0].Maximum = 99
	first.MemoryInitialPage[0] = 99

	second, err := cache.inspect(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("inspector calls = %d, want 1", calls.Load())
	}
	if second.Types[0].Params[0] != 0x7f || second.FunctionTypeIndex[0] == 99 || second.MemoryInitialPage[0] == 99 {
		t.Fatalf("cached contract shared mutable slices: %#v", second)
	}
	if _, ok := second.Exports["memory"]; !ok || second.TableLimits[0].Initial == 99 || *second.TableLimits[0].Maximum != 2 {
		t.Fatalf("cached contract shared mutable maps or table limits: %#v", second)
	}
}

func TestWASMInspectionCacheUsesBoundedLRU(t *testing.T) {
	if wasmInspectionCacheCapacity != 128 {
		t.Fatalf("default cache capacity = %d, want 128", wasmInspectionCacheCapacity)
	}
	var calls atomic.Int64
	cache := newWASMInspectionCache(2, func(module []byte) (wasmModuleContract, error) {
		calls.Add(1)
		return wasmModuleContract{Exports: map[string]wasmExportDefinition{string(module): {Kind: 0}}}, nil
	})
	for _, module := range [][]byte{[]byte("a"), []byte("b"), []byte("a"), []byte("c"), []byte("b")} {
		if _, err := cache.inspect(context.Background(), module); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("inspector calls = %d, want 4 after LRU eviction", calls.Load())
	}
	cache.mu.Lock()
	entryCount := len(cache.entries)
	cache.mu.Unlock()
	if entryCount != 2 {
		t.Fatalf("cache entries = %d, want 2", entryCount)
	}
}

func TestWASMInspectionCacheSingleFlightSharesSuccess(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	cache := newWASMInspectionCache(8, func([]byte) (wasmModuleContract, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return wasmModuleContract{Exports: map[string]wasmExportDefinition{"memory": {Kind: 0x02}}}, nil
	})
	const waiterCount = 32
	results := make(chan wasmModuleContract, waiterCount)
	errorsCh := make(chan error, waiterCount)
	var waiters sync.WaitGroup
	waiters.Add(waiterCount)
	for index := 0; index < waiterCount; index++ {
		go func() {
			defer waiters.Done()
			contract, err := cache.inspect(context.Background(), []byte("same-module"))
			results <- contract
			errorsCh <- err
		}()
	}
	<-started
	close(release)
	waiters.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	for contract := range results {
		delete(contract.Exports, "memory")
	}
	if calls.Load() != 1 {
		t.Fatalf("inspector calls = %d, want one single-flight leader", calls.Load())
	}
	contract, err := cache.inspect(context.Background(), []byte("same-module"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := contract.Exports["memory"]; !ok {
		t.Fatal("waiter mutation changed cached contract")
	}
}

func TestWASMInspectionCacheCachesStableInvalidArtifactError(t *testing.T) {
	var calls atomic.Int64
	cache := newWASMInspectionCache(8, func(module []byte) (wasmModuleContract, error) {
		calls.Add(1)
		return inspectWASMModule(module)
	})
	_, firstErr := cache.inspect(context.Background(), []byte("invalid wasm"))
	_, secondErr := cache.inspect(context.Background(), []byte("invalid wasm"))
	if firstErr == nil || secondErr == nil {
		t.Fatalf("invalid artifact errors = %v, %v", firstErr, secondErr)
	}
	if firstErr != secondErr {
		t.Fatalf("cached invalid artifact returned different stable errors: %p != %p", firstErr, secondErr)
	}
	if calls.Load() != 1 {
		t.Fatalf("inspector calls = %d, want 1", calls.Load())
	}
}

func TestWASMInspectionCacheSingleFlightSharesStableError(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	cache := newWASMInspectionCache(8, func([]byte) (wasmModuleContract, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return wasmModuleContract{}, errors.New("invalid worker artifact")
	})
	const waiterCount = 16
	errorsCh := make(chan error, waiterCount)
	for index := 0; index < waiterCount; index++ {
		go func() {
			_, err := cache.inspect(context.Background(), []byte("invalid-module"))
			errorsCh <- err
		}()
	}
	<-started
	close(release)
	var shared error
	for index := 0; index < waiterCount; index++ {
		err := <-errorsCh
		if err == nil {
			t.Fatal("single-flight invalid artifact returned nil error")
		}
		if shared == nil {
			shared = err
		} else if err != shared {
			t.Fatalf("waiter error %p differs from shared error %p", err, shared)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("inspector calls = %d, want one failing leader", calls.Load())
	}
}

func TestWASMInspectionCacheSeparatesParserVersions(t *testing.T) {
	var calls atomic.Int64
	cache := newWASMInspectionCache(8, func([]byte) (wasmModuleContract, error) {
		calls.Add(1)
		return wasmModuleContract{Exports: map[string]wasmExportDefinition{}}, nil
	})
	module := []byte("same-artifact")
	for _, parser := range []string{"parser-v1", "parser-v2", "parser-v1"} {
		if _, err := cache.inspectWithParserVersion(context.Background(), module, parser); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("inspector calls = %d, want 2 isolated parser keys", calls.Load())
	}
}

func TestWASMInspectionCacheCanceledWaiterDoesNotCancelLeader(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	cache := newWASMInspectionCache(8, func([]byte) (wasmModuleContract, error) {
		calls.Add(1)
		close(started)
		<-release
		return wasmModuleContract{Exports: map[string]wasmExportDefinition{}}, nil
	})
	leaderDone := make(chan error, 1)
	go func() {
		_, err := cache.inspect(context.Background(), []byte("same-module"))
		leaderDone <- err
	}()
	<-started
	waiterCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.inspect(waiterCtx, []byte("same-module")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader error = %v", err)
	}
	if _, err := cache.inspect(context.Background(), []byte("same-module")); err != nil {
		t.Fatalf("cached leader result error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("inspector calls = %d, want 1", calls.Load())
	}
}

func TestBuildWorkerValidationUsesWASMInspectionCache(t *testing.T) {
	original := defaultWASMInspectionCache
	var calls atomic.Int64
	defaultWASMInspectionCache = newWASMInspectionCache(8, func(module []byte) (wasmModuleContract, error) {
		calls.Add(1)
		return inspectWASMModule(module)
	})
	t.Cleanup(func() { defaultWASMInspectionCache = original })
	dir := writeFixturePackageDir(t)
	mustWrite(t, filepath.Join(dir, "manifest.json"), workerManifestJSON())
	mustWriteBytes(t, filepath.Join(dir, "workers", "echo.wasm"), minimalWorkerWASMForTest("redevplugin_worker_invoke"))
	var output bytes.Buffer
	if _, err := BuildFromDir(context.Background(), dir, &output, DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("BuildFromDir inspector calls = %d, want one across normalize/write validation", calls.Load())
	}
}

func BenchmarkWASMInspectionCache(b *testing.B) {
	module := minimalWorkerWASMForTest("redevplugin_worker_invoke")
	b.Run("raw_inspection", func(b *testing.B) {
		b.ReportAllocs()
		for index := 0; index < b.N; index++ {
			if _, err := inspectWASMModule(module); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached_hit", func(b *testing.B) {
		cache := newWASMInspectionCache(8, inspectWASMModule)
		if _, err := cache.inspect(context.Background(), module); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; index < b.N; index++ {
			if _, err := cache.inspect(context.Background(), module); err != nil {
				b.Fatal(err)
			}
		}
	})
}
