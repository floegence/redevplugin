package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/version"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestRuntimeDescriptorV3SeparatesInternalAndPublicCompatibility(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", "runtime-descriptor-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:redevplugin:runtime-descriptor-v3", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:redevplugin:runtime-descriptor-v3")
	if err != nil {
		t.Fatal(err)
	}
	catalog := version.CurrentPublicAPICatalog()
	document := map[string]any{
		"schema_version":   "runtime-descriptor-v3",
		"platform_version": version.CurrentCompatibilityVersion(),
		"target":           "linux/amd64",
		"internal": map[string]any{
			"rust_ipc":            version.RustIPCVersion,
			"contract_set_sha256": version.ContractSetSHA256,
		},
		"public_api": map[string]any{
			"worker_majors": catalog.WorkerAPIMajors,
			"features":      catalog.Features,
		},
		"binary_sha256": strings.Repeat("a", 64),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("valid descriptor rejected: %v: %s", err, encoded)
	}
	document["public_api"].(map[string]any)["worker_majors"] = []any{2}
	if err := schema.Validate(document); err == nil {
		t.Fatal("unsupported worker API major must be rejected")
	}
}
