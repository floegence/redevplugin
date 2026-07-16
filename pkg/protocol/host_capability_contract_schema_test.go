package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestHostCapabilityArtifactSchemasAreClosedVersionedAndValidatePublishedSample(t *testing.T) {
	t.Parallel()
	root := hostCapabilityRepositoryRoot(t)
	schemaNames := []string{
		"host-capability-contract-v1.schema.json",
		"host-capability-pin-v1.schema.json",
		"host-capability-manifest-v1.schema.json",
		"host-capability-compatibility-v1.schema.json",
		"host-capability-signature-v1.schema.json",
		"host-capability-notices-v1.schema.json",
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	schemaIDs := make(map[string]string, len(schemaNames))
	for _, name := range schemaNames {
		raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		id, ok := document["$id"].(string)
		if !ok || id == "" {
			t.Fatalf("%s has no schema id", name)
		}
		if err := compiler.AddResource(id, bytes.NewReader(raw)); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
		schemaIDs[name] = id
		if name == "host-capability-notices-v1.schema.json" {
			items := requireNestedObject(t, document, "items")
			if items["additionalProperties"] != false {
				t.Fatalf("%s notice items must be closed", name)
			}
			continue
		}
		if document["additionalProperties"] != false {
			t.Fatalf("%s must be a closed object", name)
		}
	}

	sampleRoot := filepath.Join(root, "testdata", "host-capability", "sample-documents-v1")
	base := filepath.Join(sampleRoot, "capabilities", "example.documents", "v1.0.0")
	samples := map[string]string{
		"host-capability-contract-v1.schema.json":      filepath.Join(base, "example.documents.v1.schema.json"),
		"host-capability-pin-v1.schema.json":           filepath.Join(sampleRoot, "host-capability.pin.json"),
		"host-capability-manifest-v1.schema.json":      filepath.Join(base, "example.documents.v1.manifest.json"),
		"host-capability-compatibility-v1.schema.json": filepath.Join(base, "example.documents.v1.compatibility.json"),
		"host-capability-signature-v1.schema.json":     filepath.Join(base, "example.documents.v1.sig"),
		"host-capability-notices-v1.schema.json":       filepath.Join(base, "example.documents.v1.notices.json"),
	}
	for schemaName, samplePath := range samples {
		schema, err := compiler.Compile(schemaIDs[schemaName])
		if err != nil {
			t.Fatalf("compile %s: %v", schemaName, err)
		}
		raw, err := os.ReadFile(samplePath)
		if err != nil {
			t.Fatalf("read %s: %v", samplePath, err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("decode %s: %v", samplePath, err)
		}
		if err := schema.Validate(value); err != nil {
			t.Fatalf("%s does not validate against %s: %v", samplePath, schemaName, err)
		}
	}
}

func TestReleaseMetadataReferencesCanonicalHostCapabilityPinSchema(t *testing.T) {
	t.Parallel()
	root := hostCapabilityRepositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "release-metadata-v4.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	contractRef := requireNestedObject(t, schema, "$defs", "host_capability_contract_ref")
	if contractRef["$ref"] != "host-capability-pin-v1.schema.json" || len(contractRef) != 1 {
		t.Fatalf("release metadata host capability ref must reuse the canonical pin schema: %#v", contractRef)
	}
}

func hostCapabilityRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
