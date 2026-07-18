package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/version"
)

func TestPublishedSemVerSchemasUseCanonicalPattern(t *testing.T) {
	root := repoRoot(t)
	for _, schemaName := range []string{
		"manifest-v5.schema.json",
		"release-metadata-v5.schema.json",
		"release-manifest-v3.schema.json",
		"ipc-v4.schema.json",
	} {
		t.Run(schemaName, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", schemaName))
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			semver := requireNestedObject(t, schema, "$defs", "semver")
			if semver["type"] != "string" || semver["pattern"] != version.StrictSemVerPattern {
				t.Fatalf("semver schema = %#v, want canonical pattern %q", semver, version.StrictSemVerPattern)
			}
		})
	}
}
