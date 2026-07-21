package protocol

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTrustedTimeSchemasAreClosedAndBounded(t *testing.T) {
	leafSchema := compilePlatformPackageSchema(t, "trusted-time-leaf-v1.schema.json")
	evidenceSchema := compilePlatformPackageSchema(t, "trusted-time-evidence-v1.schema.json")
	leaf := validTrustedTimeLeaf()
	evidence := validTrustedTimeEvidence()
	if err := leafSchema.Validate(leaf); err != nil {
		t.Fatalf("valid trusted time leaf rejected: %v", err)
	}
	if err := evidenceSchema.Validate(evidence); err != nil {
		t.Fatalf("valid trusted time evidence rejected: %v", err)
	}

	leaf["unknown"] = true
	if err := leafSchema.Validate(leaf); err == nil {
		t.Fatal("trusted time leaf accepted an unknown field")
	}
	evidence = validTrustedTimeEvidence()
	evidence["unknown"] = true
	if err := evidenceSchema.Validate(evidence); err == nil {
		t.Fatal("trusted time evidence accepted an unknown field")
	}
	evidence = validTrustedTimeEvidence()
	evidence["leaf"].(map[string]any)["nonce"] = "short"
	if err := evidenceSchema.Validate(evidence); err == nil {
		t.Fatal("trusted time evidence accepted a malformed nonce")
	}
	evidence = validTrustedTimeEvidence()
	evidence["inclusion_proof"] = make([]any, 65)
	if err := evidenceSchema.Validate(evidence); err == nil {
		t.Fatal("trusted time evidence accepted an oversized inclusion proof")
	}
	evidence = validTrustedTimeEvidence()
	evidence["checkpoint"].(map[string]any)["tree_size"] = 0
	if err := evidenceSchema.Validate(evidence); err == nil {
		t.Fatal("trusted time evidence accepted an empty checkpoint tree")
	}
}

func TestReleaseTrustStateSchemaIsClosedAndBounded(t *testing.T) {
	schema := compilePlatformPackageSchema(t, "release-trust-state-v1.schema.json")
	state := validReleaseTrustState()
	if err := schema.Validate(state); err != nil {
		t.Fatalf("valid release trust state rejected: %v", err)
	}

	invalid := validReleaseTrustState()
	invalid["unknown"] = true
	if err := schema.Validate(invalid); err == nil {
		t.Fatal("release trust state accepted an unknown field")
	}

	invalid = validReleaseTrustState()
	invalid["revision"] = 0
	if err := schema.Validate(invalid); err == nil {
		t.Fatal("release trust state accepted revision zero")
	}

	invalid = validReleaseTrustState()
	invalid["channels"] = make([]any, 17)
	if err := schema.Validate(invalid); err == nil {
		t.Fatal("release trust state accepted too many channels")
	}

	invalid = validReleaseTrustState()
	invalid["channels"] = []any{map[string]any{
		"channel": "stable",
		"policy":  validReleaseTrustDocumentHead("../escape"),
	}}
	if err := schema.Validate(invalid); err == nil {
		t.Fatal("release trust state accepted an escaping locator")
	}
}

func validTrustedTimeLeaf() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.trusted_time_leaf.v1",
		"source_id":      "example_source",
		"channel":        "stable",
		"nonce":          strings.Repeat("A", 43),
		"minimum_time":   "2026-07-21T01:00:00Z",
		"claimed_time":   "2030-07-21T01:00:00Z",
		"request_sha256": repeatedHex("1f"),
		"log_id":         "time_log",
	}
}

func validTrustedTimeEvidence() map[string]any {
	return map[string]any{
		"schema_version":         "redevplugin.trusted_time_evidence.v1",
		"kind":                   "transparency",
		"leaf":                   validTrustedTimeLeaf(),
		"leaf_sha256":            repeatedHex("2f"),
		"integrated_time":        "2026-07-21T02:00:00Z",
		"signed_entry_timestamp": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 64)),
		"checkpoint": map[string]any{
			"schema_version":  "redevplugin.trusted_time_checkpoint.v1",
			"log_id":          "time_log",
			"tree_size":       1,
			"root_hash":       repeatedHex("4f"),
			"checkpoint_time": "2026-07-21T02:00:00Z",
			"key_id":          "time_key",
			"signature":       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 64)),
		},
		"leaf_index":        0,
		"inclusion_proof":   []any{},
		"consistency_proof": []any{},
	}
}

func validReleaseTrustState() map[string]any {
	return map[string]any{
		"schema_version":   "redevplugin.release_trust_state.v1",
		"source_id":        "example_source",
		"revision":         1,
		"external_counter": 0,
		"trusted_time": map[string]any{
			"floor":             "2026-07-21T02:00:00Z",
			"checkpoint_sha256": repeatedHex("6f"),
			"checkpoint":        validTrustedTimeEvidence()["checkpoint"],
		},
		"channels": []any{map[string]any{
			"channel": "stable",
			"policy":  validReleaseTrustDocumentHead("policy/stable.json"),
		}},
	}
}

func validReleaseTrustDocumentHead(locator string) map[string]any {
	return map[string]any{
		"pointer_locator":          locator,
		"pointer_transport_token":  "pointer-etag",
		"pointer_epoch":            "1",
		"pointer_sha256":           repeatedHex("7f"),
		"document_locator":         "documents/stable.json",
		"document_transport_token": "document-etag",
		"document_sha256":          repeatedHex("8f"),
		"generated_at":             "2026-07-21T01:00:00Z",
		"expires_at":               "2026-07-22T01:00:00Z",
		"key_id":                   "policy_key",
	}
}
