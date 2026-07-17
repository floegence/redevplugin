package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/floegence/redevplugin/pkg/version"
)

func TestWASMWorkerSchemaMatchesExecutableRuntimeContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "wasm-worker-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("wasm worker schema must be closed: %#v", schema["additionalProperties"])
	}
	assertStringSet(t, requireStringSlice(t, schema["required"], "wasm worker required"), []string{
		"abi_version", "memory", "table", "exports", "imports",
	}, "wasm worker required")

	properties := requireNestedObject(t, schema, "properties")
	if got := requireNestedObject(t, properties, "abi_version")["const"]; got != version.WASMABIVersion {
		t.Fatalf("abi_version = %#v, want %q", got, version.WASMABIVersion)
	}
	memory := requireNestedObject(t, properties, "memory", "properties")
	for name, want := range map[string]any{
		"count": float64(1), "export": "memory", "memory64": false, "shared": false, "page_size_bytes": float64(65536),
	} {
		if got := requireNestedObject(t, memory, name)["const"]; got != want {
			t.Fatalf("memory.%s = %#v, want %#v", name, got, want)
		}
	}
	table := requireNestedObject(t, properties, "table", "properties")
	if got := requireNestedObject(t, table, "max_count")["const"]; got != float64(1) {
		t.Fatalf("table.max_count = %#v", got)
	}
	if got := requireNestedObject(t, table, "max_elements")["const"]; got != float64(65536) {
		t.Fatalf("table.max_elements = %#v", got)
	}

	constants := rustStringConstants(t, filepath.Join(root, "crates", "redevplugin-wasm-abi", "src", "lib.rs"))
	if constants["WASM_WORKER_ABI_VERSION"] != version.WASMABIVersion {
		t.Fatalf("rust ABI version = %q", constants["WASM_WORKER_ABI_VERSION"])
	}
	definitions := requireNestedObject(t, schema, "$defs")
	for definition, constant := range map[string]string{
		"alloc_function":   "EXPORT_WORKER_ALLOC",
		"dealloc_function": "EXPORT_WORKER_DEALLOC",
		"invoke_function":  "EXPORT_WORKER_INVOKE",
	} {
		name := requireNestedObject(t, definitions, definition, "properties", "name")["const"]
		if name != constants[constant] {
			t.Fatalf("%s name = %#v, rust %s = %q", definition, name, constant, constants[constant])
		}
	}
	assertJSONConst(t, definitions, "alloc_function", "params", []string{"i32"})
	assertJSONConst(t, definitions, "alloc_function", "results", []string{"i32"})
	assertJSONConst(t, definitions, "dealloc_function", "params", []string{"i32", "i32"})
	assertJSONConst(t, definitions, "dealloc_function", "results", []string{})
	assertJSONConst(t, definitions, "invoke_function", "params", []string{"i32", "i32"})
	assertJSONConst(t, definitions, "invoke_function", "results", []string{"i64"})

	hostcall := requireNestedObject(t, definitions, "hostcall_import", "properties")
	assertStringEnum(t, requireNestedObject(t, hostcall, "module")["enum"], "hostcall modules", []string{
		constants["IMPORT_STORAGE"], constants["IMPORT_NETWORK"],
	})
	assertStringEnum(t, requireNestedObject(t, hostcall, "name")["enum"], "hostcall names", []string{
		"files", "kv", "sqlite", "execute",
	})
	assertJSONConst(t, definitions, "hostcall_import", "params", []string{"i32", "i32", "i32", "i32"})
	assertJSONConst(t, definitions, "hostcall_import", "results", []string{"i32"})
}

func assertJSONConst(t *testing.T, definitions map[string]any, definition, property string, want []string) {
	t.Helper()
	raw := requireNestedObject(t, definitions, definition, "properties", property)["const"]
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s.%s const = %#v", definition, property, raw)
	}
	got := make([]string, len(items))
	for index, item := range items {
		got[index] = item.(string)
	}
	if !stringSetEqual(got, want) || len(got) != len(want) {
		t.Fatalf("%s.%s = %#v, want %#v", definition, property, got, want)
	}
}

func rustStringConstants(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`pub const ([A-Z0-9_]+): &str = "([^"]+)";`).FindAllStringSubmatch(string(raw), -1)
	out := map[string]string{}
	for _, match := range matches {
		out[match[1]] = match[2]
	}
	for _, name := range []string{
		"WASM_WORKER_ABI_VERSION", "EXPORT_MEMORY", "EXPORT_WORKER_ALLOC", "EXPORT_WORKER_DEALLOC",
		"EXPORT_WORKER_INVOKE", "IMPORT_STORAGE", "IMPORT_NETWORK",
	} {
		if out[name] == "" {
			t.Fatalf("missing rust wasm ABI constant %s", name)
		}
	}
	return out
}

func assertStringSet(t *testing.T, got []string, want []string, label string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if !stringSetEqual(got, want) {
		t.Fatalf("%s = %#v, want %#v", label, got, want)
	}
}
