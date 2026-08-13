package host

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/registry"
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

func TestBindRetainedDataSerializesTargetDisable(t *testing.T) {
	packageBytes := buildDataShapeFixturePackage(t, dataShapeFixtureOptions{Version: "1.0.0", SettingsSchema: 1, StorageSchema: 1})
	h, _, _ := newTestHost(t, true, true)
	source, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: "plugini_retained_source", PackageReader: bytes.NewReader(packageBytes), PackageSize: int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{
		PluginInstanceID: source.PluginInstanceID, ExpectedManagementRevision: source.ManagementRevision,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UninstallPlugin(hostTestContext(), UninstallRequest{
		PluginInstanceID:           source.PluginInstanceID,
		ExpectedManagementRevision: mustManagementRevision(t, h, source.PluginInstanceID),
	}); err != nil {
		t.Fatal(err)
	}
	retained, err := h.ListRetainedData(hostTestContext(), ListRetainedDataRequest{PluginInstanceID: source.PluginInstanceID})
	if err != nil || len(retained) != 1 {
		t.Fatalf("ListRetainedData() = %#v, %v", retained, err)
	}
	target, err := h.ImportLocalPackage(hostTestContext(), ImportLocalPackageRequest{
		PluginInstanceID: "plugini_retained_target", PackageReader: bytes.NewReader(packageBytes), PackageSize: int64(len(packageBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	pluginData := &blockingPluginData{
		PluginData:  h.adapters.PluginData,
		bindEntered: make(chan struct{}), bindRelease: make(chan struct{}),
	}
	h.adapters.PluginData = pluginData

	bindDone := make(chan error, 1)
	go func() {
		_, bindErr := h.BindRetainedData(hostTestContext(), BindRetainedDataRequest{
			SourcePluginInstanceID:           source.PluginInstanceID,
			ExpectedSourceBindingRevision:    retained[0].Revision,
			TargetPluginInstanceID:           target.PluginInstanceID,
			TargetExpectedManagementRevision: target.ManagementRevision,
		})
		bindDone <- bindErr
	}()
	waitForConcurrencyTestSignal(t, pluginData.bindEntered, "retained data bind")

	cancelQueuedLifecycleOperation(t, h, []string{target.PluginInstanceID}, "target disable", func(ctx context.Context) error {
		_, disableErr := h.DisablePlugin(ctx, DisableRequest{
			PluginInstanceID:           target.PluginInstanceID,
			ExpectedManagementRevision: target.ManagementRevision,
			Reason:                     "concurrency test",
		})
		return disableErr
	})
	cancelQueuedLifecycleOperation(t, h, []string{source.PluginInstanceID}, "source retained data delete", func(ctx context.Context) error {
		_, deleteErr := h.DeleteRetainedData(ctx, DeleteRetainedDataRequest{
			PluginInstanceID: source.PluginInstanceID, ExpectedBindingRevision: retained[0].Revision,
		})
		return deleteErr
	})
	if calls := pluginData.listRetainedCalls.Load(); calls != 0 {
		t.Fatalf("PluginData.ListRetained() calls before bind release = %d, want 0", calls)
	}
	close(pluginData.bindRelease)
	if err := <-bindDone; err != nil {
		t.Fatalf("BindRetainedData() error = %v", err)
	}
	if _, err := h.DisablePlugin(hostTestContext(), DisableRequest{
		PluginInstanceID:           target.PluginInstanceID,
		ExpectedManagementRevision: mustManagementRevision(t, h, target.PluginInstanceID),
		Reason:                     "concurrency test",
	}); err != nil {
		t.Fatalf("DisablePlugin() after bind error = %v", err)
	}
	disabled, err := h.getPluginRecord(hostTestContext(), target.PluginInstanceID)
	if err != nil || disabled.EnableState != registry.EnableDisabled {
		t.Fatalf("disabled target = %#v, err=%v", disabled, err)
	}
	if _, err := h.DeleteRetainedData(hostTestContext(), DeleteRetainedDataRequest{
		PluginInstanceID: source.PluginInstanceID, ExpectedBindingRevision: retained[0].Revision,
	}); !errors.Is(err, plugindata.ErrBindingNotFound) {
		t.Fatalf("DeleteRetainedData() error = %v, want %v", err, plugindata.ErrBindingNotFound)
	}
	if calls := pluginData.listRetainedCalls.Load(); calls != 1 {
		t.Fatalf("PluginData.ListRetained() calls after bind = %d, want 1", calls)
	}
}

type blockingPluginData struct {
	PluginData
	importEntered     chan struct{}
	importRelease     chan struct{}
	bindEntered       chan struct{}
	bindRelease       chan struct{}
	listRetainedCalls atomic.Int64
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

func (s *blockingPluginData) BindRetained(ctx context.Context, req plugindata.BindRetainedRequest) (plugindata.Dataset, error) {
	close(s.bindEntered)
	select {
	case <-ctx.Done():
		return plugindata.Dataset{}, ctx.Err()
	case <-s.bindRelease:
		return s.PluginData.BindRetained(ctx, req)
	}
}

func (s *blockingPluginData) ListRetained(ctx context.Context, filter plugindata.RetainedFilter) ([]plugindata.Binding, error) {
	s.listRetainedCalls.Add(1)
	return s.PluginData.ListRetained(ctx, filter)
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
