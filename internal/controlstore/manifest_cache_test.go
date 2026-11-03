package controlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func cacheTestManifest(t testing.TB, version string) []byte {
	t.Helper()
	value := externalControlRecord("cache", version, time.Unix(100, 0)).Manifest
	raw, err := manifest.MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManifestDecodeCacheOwnsEveryContainer(t *testing.T) {
	raw := cacheTestManifest(t, "1.0.0")
	var cache manifestDecodeCache
	first, canonical, err := cache.decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	expectedKeyword := first.Presentation.Keywords[0]
	first.Presentation.Keywords[0] = "changed"
	first.Surfaces[0].Web.Root = "changed"
	second, again, err := cache.decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != again || second.Presentation.Keywords[0] != expectedKeyword || second.Surfaces[0].Web.Root != "ui" {
		t.Fatalf("cached content was mutated: keywords=%#v root=%q canonical=%t", second.Presentation.Keywords, second.Surfaces[0].Web.Root, canonical == again)
	}
	if cache.decodes != 1 {
		t.Fatalf("validations=%d", cache.decodes)
	}
	// Exercise nested interface maps, slices and pointer fields independently of
	// schema validation so future arbitrary schema values cannot alias callers.
	original := manifest.Manifest{Methods: []manifest.MethodSpec{{RequestSchema: map[string]any{"properties": map[string]any{"rows": []any{map[string]any{"type": "string"}}}}}}, Settings: &manifest.SettingsSpec{}}
	cloned := cloneCachedManifest(original)
	cloned.Methods[0].RequestSchema["properties"].(map[string]any)["rows"].([]any)[0].(map[string]any)["type"] = "boolean"
	if reflect.DeepEqual(original, cloned) {
		t.Fatal("nested schema containers alias")
	}
}

func TestManifestDecodeCacheRejectsChangedOrInvalidBytes(t *testing.T) {
	raw := cacheTestManifest(t, "1.0.0")
	var cache manifestDecodeCache
	if _, _, err := cache.decode(raw); err != nil {
		t.Fatal(err)
	}
	bad := append(append([]byte{}, raw...), ' ')
	for i := 0; i < 2; i++ {
		if _, _, err := cache.decode(bad); err == nil {
			t.Fatal("noncanonical bytes accepted")
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["unknown_cache_field"] = true
	unknown, err := manifest.CanonicalJSON(mustJSON(t, decoded))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.decode(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
	next := cacheTestManifest(t, "1.0.1")
	got, canonical, err := cache.decode(next)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version() != "1.0.1" || !bytes.Equal(next, []byte(canonical)) {
		t.Fatal("changed version reused old content")
	}
	if len(cache.entries) != 2 {
		t.Fatalf("invalid values were cached: %d", len(cache.entries))
	}
}
func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManifestDecodeCacheCoalescesAndEvicts(t *testing.T) {
	raw := cacheTestManifest(t, "1.0.0")
	var cache manifestDecodeCache
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 10; n++ {
				value, _, err := cache.decode(raw)
				if err != nil {
					t.Error(err)
					return
				}
				value.Presentation.Keywords[0] = "caller"
			}
		}()
	}
	wg.Wait()
	if cache.decodes != 1 {
		t.Fatalf("concurrent validations=%d", cache.decodes)
	}
	for i := 1; i <= manifestCacheEntries; i++ {
		if _, _, err := cache.decode(cacheTestManifest(t, fmt.Sprintf("1.0.%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if len(cache.entries) != manifestCacheEntries || cache.bytes > manifestCacheBytes {
		t.Fatal("cache exceeded bounds")
	}
	before := cache.decodes
	if _, _, err := cache.decode(raw); err != nil {
		t.Fatal(err)
	}
	if cache.decodes != before+1 {
		t.Fatal("oldest entry was not evicted")
	}
}

func BenchmarkManifestDecodeCache(b *testing.B) {
	raw := cacheTestManifest(b, "1.0.0")
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("cached_%t", cached), func(b *testing.B) {
			var cache manifestDecodeCache
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				if cached {
					_, _, err = cache.decode(raw)
				} else {
					_, _, err = decodeExactCanonicalManifest(raw)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestManifestCacheDoesNotCacheAuthorizationState(t *testing.T) {
	record := externalControlRecord("authority", "1.0.0", time.Unix(100, 0))
	raw, err := encodeRegistryPluginRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{}
	first, err := store.decodeRegistryPluginRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	validations := store.manifests.decodes
	record.ManagementRevision++
	record.RevokeEpoch++
	raw, err = encodeRegistryPluginRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.decodeRegistryPluginRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if second.ManagementRevision != first.ManagementRevision+1 || second.RevokeEpoch != first.RevokeEpoch+1 {
		t.Fatal("immutable manifest cache retained authorization state")
	}
	if store.manifests.decodes != validations {
		t.Fatal("unchanged canonical content was reparsed")
	}
	damaged := bytes.ReplaceAll(raw, []byte("com.example"), []byte("com.invalid"))
	// A changed valid manifest must be decoded from its own bytes; it cannot
	// return the old cached identity. Invalid surrounding evidence fails closed.
	third, err := store.decodeRegistryPluginRecord(damaged)
	if err == nil && third.Manifest.Plugin.PluginID == first.Manifest.Plugin.PluginID {
		t.Fatal("changed bytes returned cached plugin identity")
	}
}
