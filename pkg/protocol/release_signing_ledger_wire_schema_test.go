package protocol

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestReleaseSigningLedgerWireSchemasAreClosed(t *testing.T) {
	subjectSchema := compilePlatformPackageSchema(t, "release-signing-subject-v1.schema.json")
	envelopeSchema := compilePlatformPackageSchema(t, "release-signature-envelope-v1.schema.json")
	receiptSchema := compilePlatformPackageSchema(t, "release-signing-ledger-receipt-v1.schema.json")
	ledgerSchema := compilePlatformPackageSchema(t, "release-signing-ledger-v1.schema.json")

	values := []struct {
		name   string
		schema interface{ Validate(any) error }
		value  map[string]any
	}{
		{"subject", subjectSchema, validSigningSubject()},
		{"envelope", envelopeSchema, validSignatureEnvelope()},
		{"receipt", receiptSchema, validSigningLedgerReceipt()},
		{"entry", ledgerSchema, validSigningLedgerEntry()},
		{"log_leaf", ledgerSchema, validSigningLedgerLogLeaf()},
		{"checkpoint", ledgerSchema, validSigningLedgerCheckpoint()},
		{"inclusion", ledgerSchema, validSigningLedgerInclusionProof()},
		{"latest", ledgerSchema, validSigningLedgerLatestProof()},
		{"consistency", ledgerSchema, validSigningLedgerConsistencyProof()},
	}
	for _, testCase := range values {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.schema.Validate(testCase.value); err != nil {
				t.Fatalf("valid %s rejected: %v", testCase.name, err)
			}
			testCase.value["unknown"] = true
			if err := testCase.schema.Validate(testCase.value); err == nil {
				t.Fatalf("%s accepted an unknown field", testCase.name)
			}
		})
	}
}

func TestReleaseSigningLedgerWireSchemasRejectCrossShapeAndOversize(t *testing.T) {
	subjectSchema := compilePlatformPackageSchema(t, "release-signing-subject-v1.schema.json")
	ledgerSchema := compilePlatformPackageSchema(t, "release-signing-ledger-v1.schema.json")

	subject := validSigningSubject()
	subject["epoch"] = "1"
	if err := subjectSchema.Validate(subject); err == nil {
		t.Fatal("release signing subject accepted epoch-only fields")
	}

	latest := validSigningLedgerLatestProof()
	delete(latest, "signature_envelope_sha256")
	if err := ledgerSchema.Validate(latest); err == nil {
		t.Fatal("present latest proof accepted a partial value")
	}

	latest = validSigningLedgerLatestProof()
	latest["siblings"] = make([]any, 257)
	if err := ledgerSchema.Validate(latest); err == nil {
		t.Fatal("latest proof accepted more than 256 sparse siblings")
	}
}

func validSigningSubject() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_subject.v1",
		"usage":          "package", "source_id": "example_source", "channel": "stable",
		"publisher_id": "example.publisher", "plugin_id": "example.plugin", "version": "1.2.3",
		"artifact_or_metadata_identity_sha256": strings.Repeat("1", 64),
	}
}

func validSigningLedgerEntry() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger_entry.v1", "state": "reserved",
		"subject": validSigningSubject(), "subject_identity_sha256": strings.Repeat("1", 64),
		"signing_preimage_sha256": strings.Repeat("2", 64), "algorithm": "ed25519",
		"key_id": "package_key", "revision": 1, "reserved_at": "2026-07-21T02:00:00Z",
	}
}

func validSigningLedgerLogLeaf() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger_log_leaf.v1", "source_id": "example_source",
		"channel": "stable", "subject_identity_sha256": strings.Repeat("1", 64),
		"signing_preimage_sha256": strings.Repeat("2", 64), "signature_envelope_sha256": strings.Repeat("3", 64),
		"sequence": 1,
	}
}

func validSignatureEnvelope() map[string]any {
	return map[string]any{
		"schema_version":          "redevplugin.release_signature_envelope.v1",
		"subject_identity_sha256": strings.Repeat("1", 64), "signing_preimage_sha256": strings.Repeat("2", 64),
		"algorithm": "ed25519", "key_id": "package_key",
		"signature": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 64)),
	}
}

func validSigningLedgerReceipt() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger_receipt.v1", "log_id": "signing_log",
		"source_id": "example_source", "channel": "stable", "subject_identity_sha256": strings.Repeat("1", 64),
		"signing_preimage_sha256": strings.Repeat("2", 64), "signature_envelope_sha256": strings.Repeat("3", 64),
		"sequence": 1, "leaf_index": 0, "tree_size": 1, "log_root_hash": strings.Repeat("4", 64),
		"latest_map_root_hash": strings.Repeat("5", 64), "checkpoint_sha256": strings.Repeat("6", 64),
		"checkpoint_time": "2026-07-21T02:00:00Z", "key_id": "ledger_key",
		"signature": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64)),
	}
}

func validSigningLedgerCheckpoint() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger.v1", "kind": "checkpoint", "log_id": "signing_log",
		"tree_size": 1, "log_root_hash": strings.Repeat("4", 64), "latest_map_root_hash": strings.Repeat("5", 64),
		"checkpoint_time": "2026-07-21T02:00:00Z", "key_id": "ledger_key",
		"signature": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64)),
	}
}

func validSigningLedgerInclusionProof() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger.v1", "kind": "inclusion_proof", "log_id": "signing_log",
		"leaf_index": 0, "tree_size": 1, "nodes": []any{},
	}
}

func validSigningLedgerLatestProof() map[string]any {
	siblings := make([]any, 256)
	for index := range siblings {
		siblings[index] = strings.Repeat("0", 64)
	}
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger.v1", "kind": "latest_proof", "log_id": "signing_log",
		"subject_identity_sha256": strings.Repeat("1", 64), "present": true, "sequence": 1,
		"signing_preimage_sha256": strings.Repeat("2", 64), "signature_envelope_sha256": strings.Repeat("3", 64),
		"siblings": siblings,
	}
}

func validSigningLedgerConsistencyProof() map[string]any {
	return map[string]any{
		"schema_version": "redevplugin.release_signing_ledger.v1", "kind": "consistency_proof", "log_id": "signing_log",
		"old_tree_size": 1, "new_tree_size": 2, "nodes": []any{strings.Repeat("8", 64)},
	}
}
