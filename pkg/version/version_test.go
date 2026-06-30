package version

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCompatibilityManifestHashesMatchContractFiles(t *testing.T) {
	manifest := CurrentCompatibilityManifest()
	if manifest.SchemaVersion != CompatibilityManifestVersion {
		t.Fatalf("schema_version = %q, want %q", manifest.SchemaVersion, CompatibilityManifestVersion)
	}
	if manifest.Matrix.BridgeSchemaVersion != BridgeSchemaVersion {
		t.Fatalf("bridge schema version = %q, want %q", manifest.Matrix.BridgeSchemaVersion, BridgeSchemaVersion)
	}
	if len(manifest.Contracts) == 0 {
		t.Fatal("compatibility manifest has no contracts")
	}

	seen := map[string]bool{}
	root := repoRoot(t)
	for _, contract := range manifest.Contracts {
		if seen[contract.ID] {
			t.Fatalf("duplicate contract id %q", contract.ID)
		}
		seen[contract.ID] = true
		if contract.Path == "" || contract.Version == "" || contract.SHA256 == "" {
			t.Fatalf("incomplete contract entry: %#v", contract)
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contract.Path)))
		if err != nil {
			t.Fatalf("read %s: %v", contract.Path, err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != contract.SHA256 {
			t.Fatalf("%s sha256 = %s, want %s", contract.Path, got, contract.SHA256)
		}
	}
	for _, id := range []string{
		"plugin-platform-openapi",
		"manifest-schema",
		"package-signature-schema",
		"token-ticket-schema",
		"iframe-bridge-schema",
		"compatibility-manifest-schema",
		"rust-ipc-schema",
		"wasm-worker-schema",
		"network-grant-schema",
		"target-classifier-fixture",
	} {
		if !seen[id] {
			t.Fatalf("compatibility manifest missing contract id %q", id)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
