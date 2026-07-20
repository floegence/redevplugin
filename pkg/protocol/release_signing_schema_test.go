package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestReleaseSigningSchemasValidateSharedClosedDocuments(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "release-signing-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Documents map[string]any `json:"documents"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}

	for document, schemaName := range map[string]string{
		"root_delegation":       "release-root-delegation-v1.schema.json",
		"source_policy":         "release-source-policy-v2.schema.json",
		"source_policy_pointer": "release-source-policy-pointer-v1.schema.json",
		"revocation":            "release-revocation-v2.schema.json",
		"revocation_pointer":    "release-revocation-pointer-v1.schema.json",
	} {
		t.Run(document, func(t *testing.T) {
			schema := compilePlatformPackageSchema(t, schemaName)
			value := fixture.Documents[document]
			if err := schema.Validate(value); err != nil {
				t.Fatalf("shared fixture rejected: %v", err)
			}
			cloned := cloneReleaseSigningValue(t, value).(map[string]any)
			cloned["unknown"] = true
			if err := schema.Validate(cloned); err == nil {
				t.Fatal("schema accepted an unknown top-level field")
			}

			for _, timestamp := range []string{
				"2026-07-20T00:00:00.000Z",
				"2026-07-20T08:00:00+08:00",
			} {
				cloned = cloneReleaseSigningValue(t, value).(map[string]any)
				cloned["generated_at"] = timestamp
				if err := schema.Validate(cloned); err == nil {
					t.Fatalf("schema accepted non-canonical timestamp %q", timestamp)
				}
			}

			if document == "source_policy_pointer" || document == "revocation_pointer" {
				for _, ref := range []string{"sources//1.json", "sources/./1.json", "sources/../1.json"} {
					cloned = cloneReleaseSigningValue(t, value).(map[string]any)
					cloned["ref"] = ref
					if err := schema.Validate(cloned); err == nil {
						t.Fatalf("schema accepted unsafe pointer ref %q", ref)
					}
				}
			}
			if document == "revocation" {
				cloned = cloneReleaseSigningValue(t, value).(map[string]any)
				revoked := cloned["revoked_releases"].([]any)[0].(map[string]any)
				revoked["publisher_id"] = "ExamplePublisher"
				if err := schema.Validate(cloned); err != nil {
					t.Fatalf("schema rejected a legacy release publisher ID: %v", err)
				}
			}
		})
	}
}

func TestReleasePointerSchemasExposeTheExactClosedFieldSet(t *testing.T) {
	want := []string{
		"schema_version",
		"source_id",
		"channel",
		"epoch",
		"previous_epoch",
		"previous_document_sha256",
		"ref",
		"document_sha256",
		"generated_at",
		"expires_at",
		"key_id",
		"signature",
	}
	for _, name := range []string{
		"release-source-policy-pointer-v1.schema.json",
		"release-revocation-pointer-v1.schema.json",
	} {
		t.Run(name, func(t *testing.T) {
			root := repoRoot(t)
			raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", name))
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			pointer := requireNestedObject(t, schema, "$defs", "pointer")
			if pointer["additionalProperties"] != false {
				t.Fatal("pointer schema is not closed")
			}
			assertStringSet(t, requireStringSlice(t, pointer["required"], "pointer required"), want, "pointer required fields")
			assertStringSet(t, objectKeys(requireNestedObject(t, pointer, "properties")), want, "pointer properties")
		})
	}
}

func TestReleaseSigningSchemaFieldsMatchGoWireDTOs(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		topLevel   reflect.Type
		nestedDefs map[string]reflect.Type
	}{
		{
			name:     "release-root-delegation-v1.schema.json",
			topLevel: reflect.TypeOf(releasecontract.RootDelegationV1{}),
			nestedDefs: map[string]reflect.Type{
				"delegated_key": reflect.TypeOf(releasecontract.RootDelegatedKey{}),
			},
		},
		{
			name:     "release-source-policy-v2.schema.json",
			topLevel: reflect.TypeOf(releasecontract.SourcePolicyV2{}),
			nestedDefs: map[string]reflect.Type{
				"active_keys": reflect.TypeOf(releasecontract.SourcePolicyActiveKeys{}),
				"limits":      reflect.TypeOf(releasecontract.SourcePolicyLimits{}),
			},
		},
		{
			name:     "release-revocation-v2.schema.json",
			topLevel: reflect.TypeOf(releasecontract.RevocationV2{}),
			nestedDefs: map[string]reflect.Type{
				"revoked_release": reflect.TypeOf(releasecontract.RevokedRelease{}),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := repoRoot(t)
			raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", testCase.name))
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			assertStringSet(t, objectKeys(requireNestedObject(t, schema, "properties")), jsonFields(t, testCase.topLevel), "top-level release signing properties")
			assertStringSet(t, requireStringSlice(t, schema["required"], "top-level release signing required"), jsonFields(t, testCase.topLevel), "top-level release signing required fields")
			for name, typ := range testCase.nestedDefs {
				definition := requireNestedObject(t, schema, "$defs", name)
				assertStringSet(t, objectKeys(requireNestedObject(t, definition, "properties")), jsonFields(t, typ), name+" properties")
				assertStringSet(t, requireStringSlice(t, definition["required"], name+" required"), jsonFields(t, typ), name+" required fields")
			}
		})
	}
}

func cloneReleaseSigningValue(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}
