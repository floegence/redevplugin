package manifest

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestCompileMethodSchemasReusesValidatedContent(t *testing.T) {
	method := MethodSpec{
		Method:         "cache.reuse",
		RequestSchema:  map[string]any{"type": "object", "additionalProperties": false},
		ResponseSchema: map[string]any{"type": "object", "additionalProperties": false},
	}
	first, err := CompileMethodSchemas(method)
	if err != nil {
		t.Fatal(err)
	}
	method.Method = "cache.same-contract-different-method"
	second, err := CompileMethodSchemas(method)
	if err != nil {
		t.Fatal(err)
	}
	if first.request != second.request || first.response != second.response {
		t.Fatal("identical validated schema content was recompiled")
	}
	if first.request == first.response {
		t.Fatal("request and response resource identities were conflated")
	}
}

func TestCompileMethodSchemasIsolatesSourceMutation(t *testing.T) {
	property := map[string]any{"type": "string"}
	schema := map[string]any{
		"type": "object", "additionalProperties": false,
		"properties": map[string]any{"value": property},
	}
	method := MethodSpec{RequestSchema: schema, ResponseSchema: schema}
	first, err := CompileMethodSchemas(method)
	if err != nil {
		t.Fatal(err)
	}
	property["type"] = "number"
	second, err := CompileMethodSchemas(method)
	if err != nil {
		t.Fatal(err)
	}
	if first.request == second.request || first.response == second.response {
		t.Fatal("changed schema content reused a stale validator")
	}
	if err := first.ValidateRequest(map[string]any{"value": "original"}); err != nil {
		t.Fatalf("source mutation changed the original validator: %v", err)
	}
	if err := second.ValidateRequest(map[string]any{"value": "original"}); err == nil {
		t.Fatal("changed request contract accepted the old value")
	}
	if err := second.ValidateResponse(map[string]any{"value": 42.0}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"request_schema", "response_schema"} {
		property["type"] = "number"
		schema["additionalProperties"] = false
		if _, err := CompileMethodSchemas(method); err != nil {
			t.Fatal(err)
		}
		invalid := map[string]any{"type": "object", "additionalProperties": true}
		candidate := method
		if name == "request_schema" {
			candidate.RequestSchema = invalid
		} else {
			candidate.ResponseSchema = invalid
		}
		if _, err := CompileMethodSchemas(candidate); err == nil || !strings.Contains(err.Error(), name+".additionalProperties") {
			t.Fatalf("invalid %s after cache hit: %v", name, err)
		}
	}
}

func TestMethodSchemaCacheEnforcesLRUAndByteLimits(t *testing.T) {
	raw := func(title string) []byte {
		return []byte(fmt.Sprintf(`{"type":"object","additionalProperties":false,"title":%q}`, title))
	}
	const name = "request_schema"
	for _, tc := range []struct {
		name           string
		entries, bytes int
	}{
		{"entries", 2, 1 << 20},
		{"bytes", 100, 2 * (len(name) + len(raw("a")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newMethodSchemaCache(tc.entries, tc.bytes)
			get := func(title string) *jsonschema.Schema {
				t.Helper()
				schema, err := cache.compile(name, raw(title))
				if err != nil {
					t.Fatal(err)
				}
				return schema
			}
			first, second := get("a"), get("b")
			if get("a") != first {
				t.Fatal("recent entry was recompiled")
			}
			get("c")
			if len(cache.entries) != 2 || cache.order.Len() != 2 || cache.bytes > tc.bytes {
				t.Fatalf("cache limits: entries=%d order=%d bytes=%d", len(cache.entries), cache.order.Len(), cache.bytes)
			}
			if _, ok := cache.entries[methodSchemaCacheKey{name: name, raw: string(raw("b"))}]; ok {
				t.Fatal("least recently used entry was retained")
			}
			if get("b") == second {
				t.Fatal("evicted entry was reused")
			}
			if get("b") == get("d") {
				t.Fatal("different content shared a validator")
			}
		})
	}
	cache := newMethodSchemaCache(2, 1)
	first, err := cache.compile(name, raw("oversized"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.compile(name, raw("oversized"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(cache.entries) != 0 || cache.bytes != 0 {
		t.Fatal("oversized entry was retained")
	}
	cache = newMethodSchemaCache(2, 1<<20)
	for range 2 {
		if _, err := cache.compile(name, []byte(`{"type":"invalid"}`)); err == nil {
			t.Fatal("invalid schema compiled")
		}
	}
	if len(cache.entries) != 0 {
		t.Fatal("failed compilation was cached")
	}
}

func TestMethodSchemaCacheConcurrentReuse(t *testing.T) {
	cache := newMethodSchemaCache(2, 1<<20)
	raw := []byte(`{"type":"object","additionalProperties":false}`)
	var wg sync.WaitGroup
	results := make([]*jsonschema.Schema, 32)
	for i := range results {
		wg.Go(func() {
			compiled, err := cache.compile("request_schema", raw)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = compiled
			if err := compiled.Validate(map[string]any{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for _, result := range results {
		if result == nil || result != results[0] {
			t.Fatal("concurrent misses recompiled identical content")
		}
	}
	for i := range raw {
		raw[i] = ' '
	}
	if len(cache.entries) != 1 {
		t.Fatal("cache did not retain its own content key")
	}
	for key := range cache.entries {
		if !strings.HasPrefix(key.raw, "{") {
			t.Fatal("caller mutation changed the cache key")
		}
	}
}
