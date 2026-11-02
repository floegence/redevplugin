package plugindata

import (
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"testing"
)

func TestKVBatchConflictRollsBackEveryMutation(t *testing.T) {
	s, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	installInternalStore(t, s, ctx, "plugini_test", shape)
	req := storage.KVBatchRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "kv", Mutations: []storage.KVMutation{{Key: "a", Value: []byte("original")}, {Key: "b", Value: []byte("second")}}}
	first, err := s.BatchKV(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	stale := "stale"
	req.Mutations = []storage.KVMutation{{Key: "a", Delete: true}, {Key: "b", Value: []byte("replacement"), ExpectedETag: &stale}}
	if _, err := s.BatchKV(ctx, req); !errors.Is(err, storage.ErrRevisionConflict) {
		t.Fatalf("stale batch: %v", err)
	}
	a, err := s.GetKV(ctx, storage.KVGetRequest{PluginInstanceID: req.PluginInstanceID, ResourceScope: req.ResourceScope, StoreID: req.StoreID, Key: "a"})
	if err != nil || a.ETag != first.ETags["a"] {
		t.Fatalf("partial batch committed: %+v %v", a, err)
	}
}
