package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/sessionctx"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestResourceScopeSchemaMatchesSessionContextContract(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "resource-scope-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema := map[string]any{}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	defs := requireNestedObject(t, schema, "$defs")
	assertStringSlicesEqual(t, schemaEnum(t, defs, "scope_kind"), []string{"user", "environment"}, "resource scope kind")
	migrationCode := requireNestedObject(t, defs, "owner_scope_migration_required_code")
	if migrationCode["const"] != sessionctx.OwnerScopeMigrationRequiredCode {
		t.Fatalf("owner scope migration code = %#v, want %q", migrationCode["const"], sessionctx.OwnerScopeMigrationRequiredCode)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource("urn:redevplugin:resource-scope-v1", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:redevplugin:resource-scope-v1")
	if err != nil {
		t.Fatal(err)
	}

	valid := []sessionctx.ResourceScope{
		{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env_hash", OwnerUserHash: "user_hash"},
		{Kind: sessionctx.ScopeEnvironment, OwnerEnvHash: "env_hash"},
	}
	for _, scope := range valid {
		if err := scope.Validate(); err != nil {
			t.Fatalf("ResourceScope.Validate(%#v) error = %v", scope, err)
		}
		roundTrip := map[string]any{}
		encoded, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatal(err)
		}
		if err := compiled.Validate(roundTrip); err != nil {
			t.Fatalf("resource scope schema rejected %#v: %v", roundTrip, err)
		}
	}

	invalid := []map[string]any{
		{"kind": "global", "owner_env_hash": "env_hash"},
		{"kind": "user", "owner_env_hash": "env_hash"},
		{"kind": "environment", "owner_env_hash": "env_hash", "owner_user_hash": "user_hash"},
		{"kind": "environment", "owner_env_hash": " env_hash "},
		{"kind": "environment", "owner_env_hash": "env_hash", "owner_session_hash": "session_hash"},
		{"kind": "user", "owner_env_hash": "env_hash", "owner_user_hash": "user_hash", "session_channel_id_hash": "channel_hash"},
	}
	for _, scope := range invalid {
		if err := compiled.Validate(scope); err == nil {
			t.Fatalf("resource scope schema accepted invalid value %#v", scope)
		}
	}
}
