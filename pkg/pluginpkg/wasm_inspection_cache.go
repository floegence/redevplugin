package pluginpkg

import (
	"container/list"
	"context"
	"crypto/sha256"
	"sync"
)

const (
	wasmInspectionCacheCapacity = 128
	// Increment this when the custom section parser or Wazero validation semantics change.
	wasmInspectionParserVersion = "redevplugin-wasm-inspector-v1"
)

type wasmInspectionCacheKey struct {
	artifactSHA256 [sha256.Size]byte
	wasmABI        string
	parserVersion  string
}

type wasmInspectionCacheEntry struct {
	key      wasmInspectionCacheKey
	contract wasmModuleContract
	err      error
}

type wasmInspectionFlight struct {
	done chan struct{}
}

type wasmModuleInspector func([]byte) (wasmModuleContract, error)

type wasmInspectionCache struct {
	mu        sync.Mutex
	capacity  int
	inspector wasmModuleInspector
	entries   map[wasmInspectionCacheKey]*list.Element
	recency   *list.List
	flights   map[wasmInspectionCacheKey]*wasmInspectionFlight
}

var defaultWASMInspectionCache = newWASMInspectionCache(wasmInspectionCacheCapacity, inspectWASMModule)

func newWASMInspectionCache(capacity int, inspector wasmModuleInspector) *wasmInspectionCache {
	if capacity <= 0 {
		panic("wasm inspection cache capacity must be positive")
	}
	if inspector == nil {
		panic("wasm module inspector is required")
	}
	return &wasmInspectionCache{
		capacity:  capacity,
		inspector: inspector,
		entries:   make(map[wasmInspectionCacheKey]*list.Element, capacity),
		recency:   list.New(),
		flights:   make(map[wasmInspectionCacheKey]*wasmInspectionFlight),
	}
}

func (c *wasmInspectionCache) inspect(ctx context.Context, module []byte, wasmABI string) (wasmModuleContract, error) {
	return c.inspectWithParserVersion(ctx, module, wasmABI, wasmInspectionParserVersion)
}

func (c *wasmInspectionCache) inspectWithParserVersion(ctx context.Context, module []byte, wasmABI string, parserVersion string) (wasmModuleContract, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	key := wasmInspectionCacheKey{
		artifactSHA256: sha256.Sum256(module),
		wasmABI:        wasmABI,
		parserVersion:  parserVersion,
	}
	for {
		if err := ctx.Err(); err != nil {
			return wasmModuleContract{}, err
		}
		c.mu.Lock()
		if element := c.entries[key]; element != nil {
			c.recency.MoveToFront(element)
			entry := element.Value.(*wasmInspectionCacheEntry)
			if entry.err != nil {
				err := entry.err
				c.mu.Unlock()
				return wasmModuleContract{}, err
			}
			contract := cloneWASMModuleContract(entry.contract)
			c.mu.Unlock()
			return contract, nil
		}
		if flight := c.flights[key]; flight != nil {
			done := flight.done
			c.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return wasmModuleContract{}, ctx.Err()
			}
		}

		flight := &wasmInspectionFlight{done: make(chan struct{})}
		c.flights[key] = flight
		moduleCopy := append([]byte(nil), module...)
		c.mu.Unlock()
		go c.runInspection(key, moduleCopy, flight)
		select {
		case <-flight.done:
			continue
		case <-ctx.Done():
			return wasmModuleContract{}, ctx.Err()
		}
	}
}

func (c *wasmInspectionCache) runInspection(key wasmInspectionCacheKey, module []byte, flight *wasmInspectionFlight) {
	contract, err := c.inspector(module)
	if err != nil {
		contract = wasmModuleContract{}
		err = &stableWASMInspectionError{message: err.Error()}
	}
	entry := &wasmInspectionCacheEntry{
		key:      key,
		contract: cloneWASMModuleContract(contract),
		err:      err,
	}

	c.mu.Lock()
	if current := c.flights[key]; current != flight {
		c.mu.Unlock()
		return
	}
	delete(c.flights, key)
	element := c.recency.PushFront(entry)
	c.entries[key] = element
	for c.recency.Len() > c.capacity {
		oldest := c.recency.Back()
		oldestEntry := oldest.Value.(*wasmInspectionCacheEntry)
		delete(c.entries, oldestEntry.key)
		c.recency.Remove(oldest)
	}
	close(flight.done)
	c.mu.Unlock()
}

type stableWASMInspectionError struct {
	message string
}

func (e *stableWASMInspectionError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func cloneWASMModuleContract(contract wasmModuleContract) wasmModuleContract {
	cloned := wasmModuleContract{
		Types:             make([]wasmFunctionType, len(contract.Types)),
		FunctionTypeIndex: append([]uint32(nil), contract.FunctionTypeIndex...),
		Imports:           append([]wasmImportFunction(nil), contract.Imports...),
		Exports:           make(map[string]wasmExportDefinition, len(contract.Exports)),
		TableLimits:       make([]wasmTableLimits, len(contract.TableLimits)),
		MemoryInitialPage: append([]uint32(nil), contract.MemoryInitialPage...),
	}
	for index, functionType := range contract.Types {
		cloned.Types[index] = wasmFunctionType{
			Params:  append([]byte(nil), functionType.Params...),
			Results: append([]byte(nil), functionType.Results...),
		}
	}
	for name, exported := range contract.Exports {
		cloned.Exports[name] = exported
	}
	for index, limits := range contract.TableLimits {
		cloned.TableLimits[index] = wasmTableLimits{Initial: limits.Initial}
		if limits.Maximum != nil {
			maximum := *limits.Maximum
			cloned.TableLimits[index].Maximum = &maximum
		}
	}
	return cloned
}
