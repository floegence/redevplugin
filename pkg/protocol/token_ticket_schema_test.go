package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/sessionctx"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestTokenTicketSchemaBindsEveryTokenKind(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "token-ticket-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	defs := requireNestedObject(t, schema, "$defs")
	tokenIDRef, ok := requireNestedObject(t, schema, "properties", "token_id")["$ref"].(string)
	if !ok || tokenIDRef != "#/$defs/token_id" {
		t.Fatalf("token-ticket schema token_id ref = %q, want #/$defs/token_id", tokenIDRef)
	}
	tokenIDPattern, ok := requireNestedObject(t, defs, "token_id")["pattern"].(string)
	if !ok || tokenIDPattern != "^(at|as|pgt|ct|hg|st)_[A-Za-z0-9_-]+$" {
		t.Fatalf("token-ticket schema token_id pattern = %q", tokenIDPattern)
	}
	tokenKinds := requireStringSlice(t, requireNestedObject(t, defs, "token_kind")["enum"], "token_kind enum")
	conditions := tokenTicketConditionsByKind(t, schema)
	if len(conditions) != len(tokenKinds) {
		t.Fatalf("token-ticket schema conditions = %d, want one per token kind %#v", len(conditions), tokenKinds)
	}
	for _, kind := range tokenKinds {
		if _, ok := conditions[kind]; !ok {
			t.Fatalf("token-ticket schema missing conditional binding for %q", kind)
		}
		audience := requireNestedObject(t, tokenTicketConditionByKind(t, schema, kind), "then", "properties", "audience")
		if kind == "handle_grant" {
			continue
		}
		forbidden := requireNestedObject(t, audience, "not")
		assertStringSet(t, requireStringSlice(t, forbidden["required"], kind+" forbidden audience fields"), []string{"resource_scope"}, kind+" forbidden audience fields")
	}
	revision := requireNestedObject(t, defs, "revision", "properties")
	for _, name := range []string{"policy_revision", "management_revision", "revoke_epoch"} {
		field := requireNestedObject(t, revision, name)
		wantMinimum := float64(0)
		if name == "revoke_epoch" {
			wantMinimum = 1
		}
		if field["minimum"] != wantMinimum || field["maximum"] != float64(9007199254740991) {
			t.Fatalf("token-ticket %s bounds = %#v", name, field)
		}
	}
	audienceProperties := requireNestedObject(t, defs, "audience", "properties")
	for _, name := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		field := requireNestedObject(t, audienceProperties, name)
		if field["minLength"] == nil && field["pattern"] == nil {
			t.Fatalf("token-ticket %s has no non-empty constraint: %#v", name, field)
		}
	}

	assertTokenTicketCondition(t, conditions, "asset_ticket", "single_use", []string{
		"plugin_id",
		"plugin_instance_id",
		"plugin_version",
		"active_fingerprint",
		"surface_id",
		"surface_instance_id",
		"entry_path",
		"entry_sha256",
		"asset_session_nonce",
		"route_role",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"runtime_generation_id",
	}, "^at_[A-Za-z0-9_-]+$")
	assertTokenTicketCondition(t, conditions, "asset_session", "reusable", []string{
		"plugin_id",
		"plugin_instance_id",
		"plugin_version",
		"active_fingerprint",
		"surface_id",
		"surface_instance_id",
		"entry_path",
		"entry_sha256",
		"asset_session_nonce",
		"route_role",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"runtime_generation_id",
	}, "^as_[A-Za-z0-9_-]+$")
	assertTokenTicketCondition(t, conditions, "plugin_gateway_token", "reusable", []string{
		"plugin_id",
		"plugin_instance_id",
		"plugin_version",
		"active_fingerprint",
		"surface_id",
		"surface_instance_id",
		"entry_path",
		"entry_sha256",
		"asset_session_nonce",
		"route_role",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"bridge_channel_id",
		"runtime_generation_id",
	}, "^pgt_[A-Za-z0-9_-]+$")
	assertTokenTicketCondition(t, conditions, "confirmation_token", "single_use", []string{
		"plugin_id",
		"plugin_instance_id",
		"plugin_version",
		"active_fingerprint",
		"surface_id",
		"surface_instance_id",
		"entry_path",
		"entry_sha256",
		"asset_session_nonce",
		"route_role",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"confirmation_id",
		"bridge_channel_id",
		"method",
		"request_hash",
		"plan_hash",
		"runtime_generation_id",
	}, "^ct_[A-Za-z0-9_-]+$")
	assertTokenTicketCondition(t, conditions, "handle_grant", "reusable", []string{
		"plugin_instance_id",
		"active_fingerprint",
		"runtime_generation_id",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"handle_id",
		"method",
		"resource_scope",
	}, "^hg_[A-Za-z0-9_-]+$")
	assertTokenTicketCondition(t, conditions, "stream_ticket", "single_use", []string{
		"plugin_id",
		"plugin_instance_id",
		"plugin_version",
		"active_fingerprint",
		"route_role",
		"owner_session_hash",
		"owner_user_hash",
		"owner_env_hash",
		"session_channel_id_hash",
		"stream_id",
		"operation_id",
		"stream_direction",
		"method",
	}, "^st_[A-Za-z0-9_-]+$")
	streamAudience := requireNestedObject(t, tokenTicketConditionByKind(t, schema, "stream_ticket"), "then", "properties", "audience")
	streamAllOf := requireObjectArray(t, streamAudience["allOf"], "stream ticket audience allOf")
	trustedParent := requireConstCondition(t, streamAllOf, "route_role", "trusted_parent", "trusted parent stream")
	assertStringSet(t, requireStringSlice(t, requireNestedObject(t, trustedParent, "then")["required"], "trusted parent stream required"), []string{
		"surface_id",
		"surface_instance_id",
		"entry_path",
		"entry_sha256",
		"asset_session_nonce",
		"bridge_channel_id",
		"runtime_generation_id",
	}, "trusted parent stream required")
}

func TestAssetTicketGoldenFixtureBindsRuntimeGeneration(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "tokens", "asset-ticket-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiled := compileTokenTicketSchema(t, root)
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(fixture); err != nil {
		t.Fatalf("asset ticket fixture does not validate against token-ticket-v3 schema: %v", err)
	}
	var record bridge.TokenRecord
	decodeStrictJSON(t, raw, &record)
	canonical, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, raw) {
		t.Fatalf("asset ticket fixture is not the canonical typed encoding\n got: %s\nwant: %s", raw, canonical)
	}
	var roundTripped bridge.TokenRecord
	decodeStrictJSON(t, canonical, &roundTripped)
	if roundTripped != record {
		t.Fatalf("asset ticket typed round trip changed the record\n got: %#v\nwant: %#v", roundTripped, record)
	}
	if fixture["token_kind"] != "asset_ticket" || fixture["use"] != "single_use" {
		t.Fatalf("asset ticket fixture identity = %#v", fixture)
	}
	audience := requireNestedObject(t, fixture, "audience")
	if audience["runtime_generation_id"] != "runtime_gen_fixture_1" {
		t.Fatalf("asset ticket runtime generation = %#v", audience["runtime_generation_id"])
	}
	for _, key := range []string{"plugin_id", "plugin_instance_id", "plugin_version", "surface_id", "surface_instance_id", "entry_path", "entry_sha256", "asset_session_nonce", "route_role", "owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		if audience[key] == nil || audience[key] == "" {
			t.Fatalf("asset ticket fixture missing audience field %q: %#v", key, audience)
		}
	}
}

func TestAssetTicketGoldenFixtureRejectsUnknownFields(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "tokens", "asset-ticket-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture["unexpected_authority"] = true
	mutated, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileTokenTicketSchema(t, root).Validate(fixture); err == nil {
		t.Fatal("token-ticket-v3 schema accepted an unknown top-level field")
	}
	decoder := json.NewDecoder(bytes.NewReader(mutated))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bridge.TokenRecord{}); err == nil {
		t.Fatal("typed token record decoder accepted an unknown top-level field")
	}
}

func TestAssetTicketGoldenFixtureRejectsResourceScope(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "tokens", "asset-ticket-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	audience := mapsClone(fixture["audience"].(map[string]any))
	audience["resource_scope"] = map[string]any{
		"kind": "user", "owner_env_hash": "owner_env_hash_injected", "owner_user_hash": "owner_user_hash_injected",
	}
	fixture["audience"] = audience
	if err := compileTokenTicketSchema(t, root).Validate(fixture); err == nil {
		t.Fatal("token-ticket-v3 accepted resource_scope on an asset ticket")
	}
}

func TestHandleGrantGoldenFixtureBindsResourceScope(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "tokens", "handle-grant-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := compileTokenTicketSchema(t, root).Validate(fixture); err != nil {
		t.Fatalf("handle grant fixture does not validate against token-ticket-v3 schema: %v", err)
	}
	var record bridge.TokenRecord
	decodeStrictJSON(t, raw, &record)
	canonical, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, raw) {
		t.Fatalf("handle grant fixture is not canonical\n got: %s\nwant: %s", raw, canonical)
	}
	if !record.Audience.ResourceScope.Matches(sessionctx.ResourceScope{
		Kind: sessionctx.ScopeUser, OwnerEnvHash: "owner_env_hash_fixture_1", OwnerUserHash: "owner_user_hash_fixture_1",
	}) {
		t.Fatalf("handle grant resource scope = %#v", record.Audience.ResourceScope)
	}
	wrongScope := fixture
	audience := mapsClone(wrongScope["audience"].(map[string]any))
	audience["resource_scope"] = map[string]any{
		"kind": "environment", "owner_env_hash": "owner_env_hash_fixture_1", "owner_user_hash": "owner_user_hash_fixture_1",
	}
	wrongScope["audience"] = audience
	if err := compileTokenTicketSchema(t, root).Validate(wrongScope); err == nil {
		t.Fatal("token-ticket-v3 accepted an environment scope with owner_user_hash")
	}
	for _, name := range []string{"owner_session_hash", "owner_user_hash", "owner_env_hash", "session_channel_id_hash"} {
		mutated := mapsClone(fixture)
		mutatedAudience := mapsClone(mutated["audience"].(map[string]any))
		mutatedAudience[name] = ""
		mutated["audience"] = mutatedAudience
		if err := compileTokenTicketSchema(t, root).Validate(mutated); err == nil {
			t.Fatalf("token-ticket-v3 accepted empty %s", name)
		}
	}
	mutated := mapsClone(fixture)
	mutatedRevision := mapsClone(mutated["revision"].(map[string]any))
	mutatedRevision["revoke_epoch"] = float64(9007199254740992)
	mutated["revision"] = mutatedRevision
	if err := compileTokenTicketSchema(t, root).Validate(mutated); err == nil {
		t.Fatal("token-ticket-v3 accepted an unsafe revoke_epoch")
	}
}

func compileTokenTicketSchema(t testing.TB, root string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join(root, "spec", "plugin", "token-ticket-v3.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	resourceScopeRaw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "resource-scope-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("https://schemas.redevplugin.dev/plugin/resource-scope-v1.schema.json", bytes.NewReader(resourceScopeRaw)); err != nil {
		t.Fatal(err)
	}
	const resource = "urn:redevplugin:test:token-ticket-v3"
	if err := compiler.AddResource(resource, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func decodeStrictJSON(t testing.TB, raw []byte, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("JSON fixture has trailing data: %v", err)
	}
}

func tokenTicketConditionByKind(t *testing.T, schema map[string]any, kind string) map[string]any {
	t.Helper()
	for _, raw := range requireObjectArray(t, schema["allOf"], "token-ticket schema allOf") {
		if requireNestedObject(t, raw, "if", "properties", "token_kind")["const"] == kind {
			return raw
		}
	}
	t.Fatalf("token-ticket schema missing %q condition", kind)
	return nil
}

type tokenTicketCondition struct {
	useConst         string
	tokenIDPattern   string
	audienceRequired []string
}

func tokenTicketConditionsByKind(t *testing.T, schema map[string]any) map[string]tokenTicketCondition {
	t.Helper()
	rawConditions, ok := schema["allOf"].([]any)
	if !ok {
		t.Fatalf("token-ticket schema allOf = %#v, want array", schema["allOf"])
	}
	out := map[string]tokenTicketCondition{}
	for _, rawCondition := range rawConditions {
		condition, ok := rawCondition.(map[string]any)
		if !ok {
			t.Fatalf("token-ticket condition = %#v, want object", rawCondition)
		}
		kind, ok := requireNestedObject(t, condition, "if", "properties", "token_kind")["const"].(string)
		if !ok || kind == "" {
			t.Fatalf("token-ticket condition missing token_kind const: %#v", condition)
		}
		if _, exists := out[kind]; exists {
			t.Fatalf("duplicate token-ticket condition for %q", kind)
		}
		then := requireNestedObject(t, condition, "then")
		useConst, ok := requireNestedObject(t, then, "properties", "use")["const"].(string)
		if !ok || useConst == "" {
			t.Fatalf("token-ticket condition %q missing use const: %#v", kind, condition)
		}
		tokenIDPattern, ok := requireNestedObject(t, then, "properties", "token_id")["pattern"].(string)
		if !ok || tokenIDPattern == "" {
			t.Fatalf("token-ticket condition %q missing token_id pattern: %#v", kind, condition)
		}
		audienceRequired := requireStringSlice(t, requireNestedObject(t, then, "properties", "audience")["required"], kind+" audience required")
		out[kind] = tokenTicketCondition{
			useConst:         useConst,
			tokenIDPattern:   tokenIDPattern,
			audienceRequired: audienceRequired,
		}
	}
	return out
}

func assertTokenTicketCondition(t *testing.T, conditions map[string]tokenTicketCondition, kind string, useConst string, requiredAudience []string, tokenIDPattern string) {
	t.Helper()
	condition, ok := conditions[kind]
	if !ok {
		t.Fatalf("missing token-ticket condition for %q", kind)
	}
	if condition.useConst != useConst {
		t.Fatalf("%s use const = %q, want %q", kind, condition.useConst, useConst)
	}
	if condition.tokenIDPattern != tokenIDPattern {
		t.Fatalf("%s token_id pattern = %q, want %q", kind, condition.tokenIDPattern, tokenIDPattern)
	}
	if !stringSetEqual(condition.audienceRequired, requiredAudience) {
		t.Fatalf("%s audience required = %#v, want %#v", kind, condition.audienceRequired, requiredAudience)
	}
}
