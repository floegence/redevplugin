package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestNetworkControlCanonicalFixtures(t *testing.T) { validateNetworkFixtures(t, "network-control") }
func TestConnectionCanonicalFixtures(t *testing.T)     { validateNetworkFixtures(t, "connections") }
func validateNetworkFixtures(t *testing.T, name string) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec/plugin/"+name+".schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("urn:network-control", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:network-control")
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(repoRoot(t), "testdata/contracts/"+name+".json"))
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
