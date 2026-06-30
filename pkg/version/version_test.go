package version

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestVerifyCompatibilityManifestAcceptsCurrentContracts(t *testing.T) {
	if err := VerifyCompatibilityManifest(CurrentCompatibilityManifest(), repoRoot(t)); err != nil {
		t.Fatalf("VerifyCompatibilityManifest() error = %v", err)
	}
}

func TestVerifyCompatibilityManifestFailsClosed(t *testing.T) {
	root := repoRoot(t)

	missing := CurrentCompatibilityManifest()
	missing.Contracts = missing.Contracts[:len(missing.Contracts)-1]
	if err := VerifyCompatibilityManifest(missing, root); !errors.Is(err, ErrCompatibilityContract) {
		t.Fatalf("missing contract error = %v, want %v", err, ErrCompatibilityContract)
	}

	tamperedHash := CurrentCompatibilityManifest()
	tamperedHash.Contracts[0].SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyCompatibilityManifest(tamperedHash, root); !errors.Is(err, ErrCompatibilityContract) {
		t.Fatalf("tampered hash error = %v, want %v", err, ErrCompatibilityContract)
	}

	tamperedPath := CurrentCompatibilityManifest()
	tamperedPath.Contracts[0].Path = "../outside"
	if err := VerifyCompatibilityManifest(tamperedPath, root); !errors.Is(err, ErrCompatibilityContract) {
		t.Fatalf("tampered path metadata error = %v, want %v", err, ErrCompatibilityContract)
	}

	driftedMatrix := CurrentCompatibilityManifest()
	driftedMatrix.Matrix.PluginHostProtocolVersion = "plugin-host-v2"
	if err := VerifyCompatibilityManifest(driftedMatrix, root); !errors.Is(err, ErrCompatibilityMatrix) {
		t.Fatalf("matrix drift error = %v, want %v", err, ErrCompatibilityMatrix)
	}
}

func TestDecodeAndVerifyCompatibilityManifestFile(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "compatibility.json")
	raw := mustMarshalCompatibilityManifest(t, CurrentCompatibilityManifest())
	if err := os.WriteFile(filename, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCompatibilityManifestFile(filename, repoRoot(t)); err != nil {
		t.Fatalf("VerifyCompatibilityManifestFile() error = %v", err)
	}
}

func TestVerifyCompatibilityManifestRejectsPathTraversalEvenIfExpected(t *testing.T) {
	err := verifyContractArtifactHash(repoRoot(t), ContractArtifact{
		ID:      "bad",
		Path:    "spec/plugin/../outside.json",
		Version: "v1",
		SHA256:  "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if !errors.Is(err, ErrCompatibilityPath) {
		t.Fatalf("path traversal error = %v, want %v", err, ErrCompatibilityPath)
	}
}

func mustMarshalCompatibilityManifest(t *testing.T, manifest CompatibilityManifest) []byte {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
