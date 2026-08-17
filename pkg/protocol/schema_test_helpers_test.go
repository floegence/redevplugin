package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func compilePluginSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	pluginDir := filepath.Join(repoRoot(t), "spec", "plugin")
	raw, err := os.ReadFile(filepath.Join(pluginDir, name))
	if err != nil {
		t.Fatal(err)
	}
	resource := "urn:redevplugin:test:" + name
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		dependency, err := os.ReadFile(filepath.Join(pluginDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var identity struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(dependency, &identity); err != nil || identity.ID == "" {
			continue
		}
		if err := compiler.AddResource(identity.ID, bytes.NewReader(dependency)); err != nil {
			t.Fatal(err)
		}
	}
	if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func mapsClone(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func requireObjectArray(t *testing.T, value any, label string) []map[string]any {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want array", label, value)
	}
	objects := make([]map[string]any, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s[%d] = %#v, want object", label, index, item)
		}
		objects[index] = object
	}
	return objects
}

func assertRequiredFields(t *testing.T, definition map[string]any, label string, fields []string) {
	t.Helper()
	required := requireStringSlice(t, definition["required"], label+" required")
	for _, field := range fields {
		if !containsRequiredString(required, field) {
			t.Fatalf("%s required missing %s: %#v", label, field, required)
		}
	}
}
