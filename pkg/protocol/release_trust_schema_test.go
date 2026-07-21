package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestReleaseSigningLedgerEvidenceSchemaIsClosedAndMatchesGoDTO(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "release-signing-ledger-evidence-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var evidence any
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	schema := compilePlatformPackageSchema(t, "release-signing-ledger-evidence-v1.schema.json")
	if err := schema.Validate(evidence); err != nil {
		t.Fatalf("shared evidence rejected: %v", err)
	}

	cloned := cloneReleaseSigningValue(t, evidence).(map[string]any)
	cloned["unknown"] = true
	if err := schema.Validate(cloned); err == nil {
		t.Fatal("schema accepted an unknown field")
	}
	cloned = cloneReleaseSigningValue(t, evidence).(map[string]any)
	delete(cloned, "channel")
	if err := schema.Validate(cloned); err != nil {
		t.Fatalf("schema rejected root-delegation evidence without channel: %v", err)
	}
	cloned = cloneReleaseSigningValue(t, evidence).(map[string]any)
	delete(cloned, "consistency_proof_sha256")
	if err := schema.Validate(cloned); err == nil {
		t.Fatal("schema accepted a partial consistency proof locator pair")
	}
	for _, ref := range []string{"https://example.invalid/proof", "/proof", "proof/../swap", "proof?raw=1"} {
		cloned = cloneReleaseSigningValue(t, evidence).(map[string]any)
		cloned["receipt_ref"] = ref
		if err := schema.Validate(cloned); err == nil {
			t.Fatalf("schema accepted unsafe receipt_ref %q", ref)
		}
	}

	schemaRaw, err := os.ReadFile(filepath.Join(root, "spec", "plugin", "release-signing-ledger-evidence-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument map[string]any
	if err := json.Unmarshal(schemaRaw, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	properties := requireNestedObject(t, schemaDocument, "properties")
	assertStringSet(t, objectKeys(properties), jsonFields(t, reflect.TypeOf(releasecontract.SigningLedgerEvidenceV1{})), "ledger evidence properties")
	assertStringSet(t, requireStringSlice(t, schemaDocument["required"], "ledger evidence required"), []string{
		"schema_version",
		"source_id",
		"subject_identity_sha256",
		"signing_preimage_sha256",
		"signature_envelope_sha256",
		"receipt_ref",
		"receipt_sha256",
		"checkpoint_ref",
		"checkpoint_sha256",
		"inclusion_proof_ref",
		"inclusion_proof_sha256",
		"latest_proof_ref",
		"latest_proof_sha256",
	}, "ledger evidence required fields")
}
