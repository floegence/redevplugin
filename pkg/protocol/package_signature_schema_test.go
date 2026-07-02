package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/trust"
	"github.com/floegence/redevplugin/pkg/version"
)

func TestPackageSignatureSchemaMatchesGoSigningContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "package-signature-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	if schema["additionalProperties"] != false {
		t.Fatalf("package signature schema additionalProperties = %#v, want false", schema["additionalProperties"])
	}
	if id, ok := schema["$id"].(string); !ok || !strings.Contains(id, version.PackageSignatureSchemaVersion) {
		t.Fatalf("package signature $id = %#v, want to contain %q", schema["$id"], version.PackageSignatureSchemaVersion)
	}
	props := requireNestedObject(t, schema, "properties")
	assertStringSet(t, objectKeys(props), jsonFields(t, reflect.TypeOf(pluginpkg.PackageSignature{})), "package signature schema properties")

	required := requireStringSlice(t, schema["required"], "package signature required")
	assertStringSet(t, required, []string{
		"schema_version",
		"algorithm",
		"key_id",
		"package_hash",
		"manifest_hash",
		"entries_hash",
		"signature",
	}, "package signature required fields")

	if got := requireNestedObject(t, props, "schema_version")["const"]; got != pluginpkg.PackageSignatureSchemaVersion {
		t.Fatalf("schema_version const = %#v, want %q", got, pluginpkg.PackageSignatureSchemaVersion)
	}
	algorithm := requireStringSlice(t, requireNestedObject(t, props, "algorithm")["enum"], "package signature algorithm enum")
	assertStringSet(t, algorithm, []string{pluginpkg.PackageSignatureAlgorithmEd25519}, "package signature algorithm enum")
	if trust.AlgorithmEd25519 != pluginpkg.PackageSignatureAlgorithmEd25519 {
		t.Fatalf("trust algorithm = %q, package algorithm = %q", trust.AlgorithmEd25519, pluginpkg.PackageSignatureAlgorithmEd25519)
	}

	for _, name := range []string{"key_id", "publisher_id", "plugin_id", "signature"} {
		property := requireNestedObject(t, props, name)
		if property["type"] != "string" || property["minLength"] != float64(1) {
			t.Fatalf("%s property = %#v, want string minLength 1", name, property)
		}
	}
	for _, name := range []string{"package_hash", "manifest_hash", "entries_hash"} {
		property := requireNestedObject(t, props, name)
		if property["$ref"] != "#/$defs/sha256" {
			t.Fatalf("%s ref = %#v, want #/$defs/sha256", name, property["$ref"])
		}
	}
	signedAt := requireNestedObject(t, props, "signed_at")
	if signedAt["type"] != "string" || signedAt["format"] != "date-time" {
		t.Fatalf("signed_at property = %#v, want string date-time", signedAt)
	}
	sha256Def := requireNestedObject(t, schema, "$defs", "sha256")
	if sha256Def["type"] != "string" || sha256Def["pattern"] != "^sha256:[a-f0-9]{64}$" {
		t.Fatalf("sha256 definition = %#v", sha256Def)
	}
}

func jsonFields(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			t.Fatalf("empty json tag on %s", typ.Field(i).Name)
		}
		fields = append(fields, name)
	}
	return fields
}

func objectKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	return keys
}
