package host

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestImportPluginDataSerializesPluginUpdate(t *testing.T) {
	v1 := buildDataShapeFixturePackage(t, dataShapeFixtureOptions{Version: "1.0.0", SettingsSchema: 1, StorageSchema: 1})
	v2 := buildDataShapeFixturePackage(t, dataShapeFixtureOptions{Version: "2.0.0", SettingsSchema: 1, StorageSchema: 1})
	h, _, _ := newTestHost(t, true, true)
	installed := installAndEnablePlugin(t, h, v1)
	disabled, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           installed.PluginInstanceID,
		ExpectedManagementRevision: mustManagementRevision(t, h, installed.PluginInstanceID),
		Reason:                     "prepare import",
	})
	if err != nil {
		t.Fatal(err)
	}
	exported, err := h.ExportPluginData(hostTestContext(), ExportDataRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	pluginData := &blockingPluginData{
		PluginData:    h.adapters.PluginData,
		importEntered: make(chan struct{}), importRelease: make(chan struct{}),
	}
	h.adapters.PluginData = pluginData

	importDone := make(chan error, 1)
	go func() {
		_, importErr := h.ImportPluginData(hostTestContext(), ImportDataRequest{
			PluginInstanceID: disabled.PluginInstanceID, BundleRef: exported.BundleRef,
			ExpectedManagementRevision: disabled.ManagementRevision,
		})
		importDone <- importErr
	}()
	waitForConcurrencyTestSignal(t, pluginData.importEntered, "plugin data import")

	runUpdate := func(ctx context.Context, revision uint64) (registry.PluginRecord, error) {
		return h.UpdateLocalPackage(ctx, UpdateLocalPackageRequest{
			PluginInstanceID: disabled.PluginInstanceID, ExpectedManagementRevision: revision,
			PackageReader: bytes.NewReader(v2), PackageSize: int64(len(v2)),
		})
	}
	cancelQueuedLifecycleOperation(t, h, []string{disabled.PluginInstanceID}, "plugin update", func(ctx context.Context) error {
		_, updateErr := runUpdate(ctx, disabled.ManagementRevision)
		return updateErr
	})
	close(pluginData.importRelease)
	if err := <-importDone; err != nil {
		t.Fatalf("ImportPluginData() error = %v", err)
	}
	updated, err := runUpdate(hostTestContext(), mustManagementRevision(t, h, disabled.PluginInstanceID))
	if err != nil {
		t.Fatalf("UpdateLocalPackage() after import error = %v", err)
	}
	if updated.Version != "2.0.0" {
		t.Fatalf("updated version = %q, want 2.0.0", updated.Version)
	}
}

type blockingPluginData struct {
	PluginData
	importEntered chan struct{}
	importRelease chan struct{}
}

func (s *blockingPluginData) Import(ctx context.Context, req plugindata.ImportRequest) (plugindata.Dataset, error) {
	close(s.importEntered)
	select {
	case <-ctx.Done():
		return plugindata.Dataset{}, ctx.Err()
	case <-s.importRelease:
		return s.PluginData.Import(ctx, req)
	}
}

func waitForConcurrencyTestSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("%s did not reach the blocking adapter", operation)
	}
}

func cancelQueuedLifecycleOperation(t *testing.T, h *Host, keys []string, operation string, run func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(hostTestContext())
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	waitForQueuedLifecycleOperation(t, h.lifecycleLocks, keys, operation)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled %s error = %v, want %v", operation, err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatalf("canceled %s did not return while the conflicting adapter remained blocked", operation)
	}
	assertNoQueuedLifecycleOperation(t, h.lifecycleLocks, keys, operation)
}

func waitForQueuedLifecycleOperation(t *testing.T, locks *pluginLifecycleLockRegistry, keys []string, operation string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		locks.mu.Lock()
		queued := lifecycleWaiterQueued(locks.waiters, keys)
		locks.mu.Unlock()
		if queued {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not enter the lifecycle lock wait queue", operation)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertNoQueuedLifecycleOperation(t *testing.T, locks *pluginLifecycleLockRegistry, keys []string, operation string) {
	t.Helper()
	locks.mu.Lock()
	queued := lifecycleWaiterQueued(locks.waiters, keys)
	locks.mu.Unlock()
	if queued {
		t.Fatalf("canceled %s remained in the lifecycle lock wait queue", operation)
	}
}

func lifecycleWaiterQueued(waiters []*pluginLifecycleWaiter, keys []string) bool {
	normalized, err := normalizePluginLifecycleKeys(keys)
	if err != nil {
		return false
	}
	for _, waiter := range waiters {
		if len(waiter.keys) != len(normalized) {
			continue
		}
		matches := true
		for index := range normalized {
			if waiter.keys[index] != normalized[index] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}
