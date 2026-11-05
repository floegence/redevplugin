package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/releasepublisher"
)

func TestReleasePublisherSchemasMatchGoWireDTOs(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		topLevel   reflect.Type
		nestedDefs map[string]reflect.Type
	}{
		{
			name:       "presentation-icon-evidence-v1.schema.json",
			topLevel:   reflect.TypeOf(releasepublisher.PresentationIconEvidenceV1{}),
			nestedDefs: map[string]reflect.Type{},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", testCase.name))
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			assertStringSet(t, objectKeys(requireNestedObject(t, schema, "properties")), publisherJSONFields(t, testCase.topLevel), "top-level publisher properties")
			assertStringSet(t, requireStringSlice(t, schema["required"], "top-level publisher required"), publisherJSONFields(t, testCase.topLevel), "top-level publisher required fields")
			for name, typ := range testCase.nestedDefs {
				definition := requireNestedObject(t, schema, "$defs", name)
				assertStringSet(t, objectKeys(requireNestedObject(t, definition, "properties")), publisherJSONFields(t, typ), name+" properties")
			}
		})
	}
}

func publisherJSONFields(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if tag == "" && field.Anonymous {
			fields = append(fields, publisherJSONFields(t, field.Type)...)
			continue
		}
		if tag == "" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			t.Fatalf("empty json tag on %s", field.Name)
		}
		fields = append(fields, name)
	}
	return fields
}

func TestReleasePublisherSchemasValidateRepresentativeDocuments(t *testing.T) {
	iconEvidence := releasepublisher.PresentationIconEvidenceV1{
		SchemaVersion: releasepublisher.PresentationIconEvidenceSchemaVersion,
		Path:          "ui/assets/plugin.png",
		MediaType:     "image/png",
		Width:         128,
		Height:        128,
		SHA256:        "sha256:" + strings.Repeat("6", 64),
		Size:          1024,
	}
	for name, document := range map[string]any{
		"presentation-icon-evidence-v1.schema.json": iconEvidence,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			if err := compilePluginSchema(t, name).Validate(value); err != nil {
				t.Fatalf("representative publisher document rejected: %v", err)
			}
			value.(map[string]any)["unknown"] = true
			if err := compilePluginSchema(t, name).Validate(value); err == nil {
				t.Fatal("schema accepted an unknown top-level field")
			}
		})
	}
}
