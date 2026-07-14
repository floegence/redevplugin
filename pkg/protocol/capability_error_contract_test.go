package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestBridgeCapabilityBusinessErrorDetailsAreClosedAndMatchFixture(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	schema := readJSONMap(t, filepath.Join(root, "spec", "plugin", "bridge-v2.schema.json"))
	detailsSchema := requireNestedObject(t, schema, "$defs", "capability_business_error_details")
	if detailsSchema["additionalProperties"] != false {
		t.Fatalf("capability business error details must be closed: %#v", detailsSchema)
	}
	want := []string{
		"capability_id",
		"capability_version",
		"detail_schema_sha256",
		"business_error_code",
	}
	assertStringSet(t, requireStringSlice(t, detailsSchema["required"], "capability business error required"), want, "capability business error required")

	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "capability-business-error-details-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	properties := requireNestedObject(t, detailsSchema, "properties")
	for key := range fixture {
		if _, ok := properties[key]; !ok {
			t.Fatalf("business error fixture field %q is absent from bridge schema", key)
		}
	}
	detailsRaw, err := json.Marshal(detailsSchema)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	const resource = "urn:redevplugin:test:capability-business-error-details"
	if err := compiler.AddResource(resource, bytes.NewReader(detailsRaw)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(resource)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(fixture); err != nil {
		t.Fatalf("business error fixture does not validate: %v", err)
	}
	fixture["unexpected"] = true
	if err := compiled.Validate(fixture); err == nil {
		t.Fatal("capability business error schema accepted an unknown field")
	}
}

func TestOpenAPICapabilityErrorsAndSubscriptionResultsMatchBridgeContract(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "openapi", "plugin-platform-v2.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	details := openAPISchemaBlock(t, text, "CapabilityBusinessErrorDetails")
	for _, snippet := range []string{
		"additionalProperties: false",
		"required: [capability_id, capability_version, detail_schema_sha256, business_error_code]",
		"business_error_details:",
	} {
		if !strings.Contains(details, snippet) {
			t.Fatalf("CapabilityBusinessErrorDetails missing %q:\n%s", snippet, details)
		}
	}
	rpcResult := openAPISchemaBlock(t, text, "RPCResult")
	if !strings.Contains(rpcResult, "required: [operation_id, stream_id, stream_ticket, stream_ticket_id, stream_expires_at]") {
		t.Fatalf("RPCResult subscription variant must bind operation and stream handles:\n%s", rpcResult)
	}
	if !strings.Contains(text, `"200": { $ref: "#/components/responses/RPCEnvelope" }`) {
		t.Fatal("plugin RPC route does not use the typed RPCEnvelope")
	}
}
