package plugindata

import (
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"testing"
)

func TestKVConditionalWritesPreserveConcurrentEdit(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	installInternalStore(t, store, ctx, "plugini_test", shape)
	absent := ""
	req := storage.KVPutRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Key: "draft", Value: []byte("first"), ExpectedETag: &absent}
	first, err := store.PutKV(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.ETag == "" {
		t.Fatal("missing ETag")
	}
	if _, err := store.PutKV(ctx, req); !errors.Is(err, storage.ErrRevisionConflict) {
		t.Fatalf("create-only overwrite: %v", err)
	}
	req.ExpectedETag = &first.ETag
	req.Value = []byte("second")
	second, err := store.PutKV(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.ETag == second.ETag {
		t.Fatal("content ETag did not change")
	}
	req.Value = []byte("stale")
	if _, err := store.PutKV(ctx, req); !errors.Is(err, storage.ErrRevisionConflict) {
		t.Fatalf("stale write: %v", err)
	}
	if err := store.DeleteKV(ctx, storage.KVDeleteRequest{PluginInstanceID: req.PluginInstanceID, ResourceScope: req.ResourceScope, StoreID: req.StoreID, Key: req.Key, ExpectedETag: &first.ETag}); !errors.Is(err, storage.ErrRevisionConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	current, err := store.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: req.PluginInstanceID, ResourceScope: req.ResourceScope, StoreID: req.StoreID, Key: req.Key})
	if err != nil {
		t.Fatal(err)
	}
	if string(current.Value) != "second" || current.ETag != second.ETag {
		t.Fatalf("concurrent edit lost: %+v", current)
	}
}
