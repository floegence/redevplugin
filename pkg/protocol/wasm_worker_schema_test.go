package protocol

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/version"
)

func TestWASMWorkerSchemaMatchesRuntimeContracts(t *testing.T) {
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
		t.Fatalf("wasm worker schema additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	required := requireStringSlice(t, schema["required"], "wasm worker required")
	if !stringSetEqual(required, []string{"abi_version", "exports", "imports"}) {
		t.Fatalf("wasm worker required = %#v", required)
	}

	props := requireNestedObject(t, schema, "properties")
	abiVersion := requireNestedObject(t, props, "abi_version")["const"]
	if abiVersion != version.WASMABIVersion {
		t.Fatalf("abi_version const = %#v, want %q", abiVersion, version.WASMABIVersion)
	}

	rustABIConstants := rustStringConstants(t, filepath.Join(root, "crates", "redevplugin-wasm-abi", "src", "lib.rs"))
	if abiVersion != rustABIConstants["WASM_WORKER_ABI_VERSION"] {
		t.Fatalf("abi_version const = %#v, rust abi const = %q", abiVersion, rustABIConstants["WASM_WORKER_ABI_VERSION"])
	}

	exports := requireNestedObject(t, props, "exports")
	assertArrayUniqueItems(t, exports, "exports")
	exportEnum := []string{requireNestedObject(t, exports, "items")["const"].(string)}
	goExports := goStringMapKeysFromReturn(t, filepath.Join(root, "pkg", "pluginpkg", "package.go"), "allowedWorkerABIExports")
	assertStringSet(t, exportEnum, goExports, "wasm worker export enum")
	rustExports := []string{
		rustABIConstants["EXPORT_WORKER_INVOKE"],
		rustABIConstants["REQUIRED_EXPORT_INVOKE"],
	}
	assertAllStringsPresent(t, exportEnum, rustExports, "rust wasm abi exports")

	workerInvocationExports := workerInvocationExportEnum(t, root)
	assertStringSet(t, workerInvocationExports, exportEnum, "worker invocation export enum")
	assertRustSourceContainsAll(t, filepath.Join(root, "crates", "redevplugin-ipc", "src", "lib.rs"), exportEnum, "rust ipc worker exports")

	imports := requireNestedObject(t, props, "imports")
	assertArrayUniqueItems(t, imports, "imports")
	importEnum := requireStringSlice(t, requireNestedObject(t, imports, "items")["enum"], "wasm worker import enum")
	goImports := goStringMapKeysFromReturn(t, filepath.Join(root, "pkg", "pluginpkg", "package.go"), "allowedWorkerABIImports")
	assertStringSet(t, importEnum, goImports, "wasm worker import enum")
	rustImports := []string{
		rustABIConstants["IMPORT_STORAGE"],
		rustABIConstants["IMPORT_NETWORK"],
	}
	assertStringSet(t, importEnum, rustImports, "rust wasm abi imports")

	runtimeLinkedModules := rustRuntimeHostcallModules(t, filepath.Join(root, "crates", "redevplugin-runtime", "src", "main.rs"))
	assertAllStringsPresent(t, importEnum, runtimeLinkedModules, "rust runtime linked hostcall modules")
}

func assertArrayUniqueItems(t *testing.T, schema map[string]any, label string) {
	t.Helper()
	if schema["type"] != "array" {
		t.Fatalf("%s type = %#v, want array", label, schema["type"])
	}
	if schema["uniqueItems"] != true {
		t.Fatalf("%s uniqueItems = %#v, want true", label, schema["uniqueItems"])
	}
}

func workerInvocationExportEnum(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "worker-invocation-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	exportSchema := requireNestedObject(t, schema, "properties", "export")
	if value, ok := exportSchema["const"].(string); ok {
		return []string{value}
	}
	return requireStringSlice(t, exportSchema["enum"], "worker invocation export enum")
}

func goStringMapKeysFromReturn(t *testing.T, path string, funcName string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				continue
			}
			lit, ok := ret.Results[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			keys := make([]string, 0, len(lit.Elts))
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					t.Fatalf("%s return map contains non key-value element %#v", funcName, elt)
				}
				key, ok := kv.Key.(*ast.BasicLit)
				if !ok || key.Kind != token.STRING {
					t.Fatalf("%s return map key = %#v, want string literal", funcName, kv.Key)
				}
				text, err := strconv.Unquote(key.Value)
				if err != nil {
					t.Fatal(err)
				}
				keys = append(keys, text)
			}
			sort.Strings(keys)
			return keys
		}
		t.Fatalf("%s does not return a string-keyed map literal", funcName)
	}
	t.Fatalf("missing function %s in %s", funcName, path)
	return nil
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
		"WASM_WORKER_ABI_VERSION",
		"EXPORT_WORKER_INVOKE",
		"REQUIRED_EXPORT_INVOKE",
		"IMPORT_STORAGE",
		"IMPORT_NETWORK",
	} {
		if out[name] == "" {
			t.Fatalf("missing rust wasm abi string constant %s in %s", name, path)
		}
	}
	return out
}

func rustRuntimeHostcallModules(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?s)\.func_wrap\(\s*"([^"]+)"`).FindAllStringSubmatch(string(raw), -1)
	seen := map[string]struct{}{}
	for _, match := range matches {
		if strings.HasPrefix(match[1], "redevplugin.") {
			seen[match[1]] = struct{}{}
		}
	}
	if len(seen) == 0 {
		t.Fatalf("no redevplugin hostcall modules found in %s", path)
	}
	modules := make([]string, 0, len(seen))
	for module := range seen {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	return modules
}

func assertStringSet(t *testing.T, got []string, want []string, label string) {
	t.Helper()
	if !stringSetEqual(got, want) {
		t.Fatalf("%s = %#v, want %#v", label, got, want)
	}
}

func assertAllStringsPresent(t *testing.T, values []string, required []string, label string) {
	t.Helper()
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, item := range required {
		if !seen[item] {
			t.Fatalf("%s missing %q in %#v", label, item, values)
		}
	}
}

func assertRustSourceContainsAll(t *testing.T, path string, required []string, label string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, item := range required {
		if !strings.Contains(source, strconv.Quote(item)) {
			t.Fatalf("%s missing %q in %s", label, item, path)
		}
	}
}
