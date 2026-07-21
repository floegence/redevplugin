package releasecontract

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSigningLedgerEvidenceClosedCanonicalRoundTrip(t *testing.T) {
	raw := readSigningLedgerEvidenceFixture(t)
	var evidence SigningLedgerEvidenceV1
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalSigningLedgerEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSigningLedgerEvidence(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != evidence {
		t.Fatalf("decoded evidence = %#v", decoded)
	}

	var value map[string]any
	if err := json.Unmarshal(canonical, &value); err != nil {
		t.Fatal(err)
	}
	value["unknown"] = true
	tampered, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSigningLedgerEvidence(tampered); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("unknown field error = %v", err)
	}

	evidence.ConsistencyProofSHA256 = ""
	if _, err := CanonicalSigningLedgerEvidence(evidence); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("partial consistency pair error = %v", err)
	}
}

func readSigningLedgerEvidenceFixture(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "release-signing-ledger-evidence-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
