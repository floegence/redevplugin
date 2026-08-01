package protocol_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/capabilitypublisher"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestHostCapabilityPublisherExchangeSchemasAreClosed(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "spec", "plugin")
	request := capabilitypublisher.SignerRequestV1{
		SchemaVersion: capabilitypublisher.RequestSchemaVersion,
		RequestID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Usage:         capabilitypublisher.SigningUsage, KeyID: "release_key", PublisherID: "example.publisher",
		ContractID: "example.contract.v1", ContractVersion: "1.0.0",
		ManifestSHA256:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SigningPreimageSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SigningPreimage:       "e30K",
	}
	response := capabilitypublisher.SignerResponseV1{
		SchemaVersion: capabilitypublisher.ResponseSchemaVersion,
		RequestID:     request.RequestID, Usage: request.Usage, KeyID: request.KeyID, PublisherID: request.PublisherID,
		ContractID: request.ContractID, ContractVersion: request.ContractVersion, ManifestSHA256: request.ManifestSHA256,
		SigningPreimageSHA256: request.SigningPreimageSHA256, Algorithm: "ed25519",
		Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
	}
	config := map[string]any{
		"schema_version": capabilitypublisher.ConfigSchemaVersion,
		"contract_file":  "contract.json", "public_key_file": "public.json",
		"artifact_base_ref": "capabilities/example/v1.0.0", "generated_at": "2026-08-01T00:00:00Z",
		"source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "min_redevplugin_version": "0.6.23",
		"signature_policy_epoch": "1", "signature_revocation_epoch": "1",
	}
	for name, value := range map[string]any{
		"host-capability-publisher-config-v1.schema.json": config,
		"host-capability-signer-request-v1.schema.json":   request,
		"host-capability-signer-response-v1.schema.json":  response,
	} {
		schema := compileHostCapabilityPublisherSchema(t, filepath.Join(root, name))
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(document); err != nil {
			t.Fatalf("%s rejected Go projection: %v", name, err)
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		object["unexpected"] = true
		if err := schema.Validate(object); err == nil {
			t.Fatalf("%s accepted an unknown field", name)
		}
	}
}

func compileHostCapabilityPublisherSchema(t *testing.T, filename string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:redevplugin:host-capability-publisher", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:redevplugin:host-capability-publisher")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
