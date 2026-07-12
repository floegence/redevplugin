package host

import (
	"testing"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/registry"
)

func TestMethodSchemaCacheEnforcesLRUCapacity(t *testing.T) {
	cache := newMethodSchemaCache(2)
	method := func(name string) manifest.MethodSpec {
		return manifest.MethodSpec{
			Method: name,
			RequestSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
			ResponseSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
		}
	}
	record := func(fingerprint string) registry.PluginRecord {
		return registry.PluginRecord{ActiveFingerprint: fingerprint}
	}

	first, err := cache.get(record("fingerprint-a"), method("method-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.get(record("fingerprint-b"), method("method-b"))
	if err != nil {
		t.Fatal(err)
	}
	firstAgain, err := cache.get(record("fingerprint-a"), method("method-a"))
	if err != nil {
		t.Fatal(err)
	}
	if firstAgain != first {
		t.Fatal("cache miss for recently used method schema")
	}
	if _, err := cache.get(record("fingerprint-c"), method("method-c")); err != nil {
		t.Fatal(err)
	}
	if cache.order.Len() != 2 || len(cache.entries) != 2 {
		t.Fatalf("cache size = order %d entries %d, want 2", cache.order.Len(), len(cache.entries))
	}
	if _, ok := cache.entries["fingerprint-b\x00method-b"]; ok {
		t.Fatal("least recently used method schema was not evicted")
	}
	if _, ok := cache.entries["fingerprint-a\x00method-a"]; !ok {
		t.Fatal("recently used method schema was evicted")
	}
	secondAgain, err := cache.get(record("fingerprint-b"), method("method-b"))
	if err != nil {
		t.Fatal(err)
	}
	if secondAgain == second {
		t.Fatal("evicted method schema unexpectedly retained its compiled entry")
	}
}
