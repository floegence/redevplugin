package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestFileResourcesCanonicalFixtures(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec/plugin/file-resources.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("urn:files", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:files")
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(repoRoot(t), "testdata/contracts/file-resources.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Valid   []any
		Invalid []any
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, value := range fixtures.Valid {
		if err := schema.Validate(value); err != nil {
			t.Fatalf("valid fixture: %v", err)
		}
	}
	for _, value := range fixtures.Invalid {
		if err := schema.Validate(value); err == nil {
			t.Fatalf("accepted invalid fixture: %+v", value)
		}
	}
}
