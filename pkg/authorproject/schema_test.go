package authorproject

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestCanonicalProjectSchemaMatchesConfiguration(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../spec/plugin/author-project-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"unknown", func(v map[string]any) { v["unexpected"] = true }, false},
		{"case alias", func(v map[string]any) { v["Build"] = v["build"]; delete(v, "build") }, false},
		{"traversal", func(v map[string]any) { v["output"] = "../outside" }, false},
		{"empty command", func(v map[string]any) { v["build"] = []string{} }, false},
		{"blank executable", func(v map[string]any) { v["build"] = []string{" "} }, false},
		{"nul argument", func(v map[string]any) { v["test"] = []string{"node", string(rune(0))} }, false},
		{"absolute input", func(v map[string]any) { v["watch"] = []string{"/tmp"} }, false},
		{"duplicate input", func(v map[string]any) { v["watch"] = []string{"ui", "ui"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := map[string]any{"schema_version": SchemaVersion, "output": "dist", "build": []string{"node", "build.mjs"}, "test": []string{"node", "test.mjs"}, "watch": []string{"ui"}}
			tc.mutate(value)
			raw, _ := json.Marshal(value)
			var decoded any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if valid := schema.Validate(decoded) == nil; valid != tc.valid {
				t.Fatalf("schema accepted=%v, want %v", valid, tc.valid)
			}
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ConfigFile), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(root); (err == nil) != tc.valid {
				t.Fatalf("Go load error=%v, want valid %v", err, tc.valid)
			}
		})
	}
}
