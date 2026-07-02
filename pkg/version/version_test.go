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
		"release-manifest-schema",
		"worker-invocation-schema",
		"error-codes-schema",
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

func TestCompatibilityManifestUsesDedicatedNetworkGrantSchemaVersion(t *testing.T) {
	manifest := CurrentCompatibilityManifest()
	if manifest.Matrix.NetworkGrantSchemaVersion != NetworkGrantSchemaVersion {
		t.Fatalf("network grant matrix version = %q, want %q", manifest.Matrix.NetworkGrantSchemaVersion, NetworkGrantSchemaVersion)
	}
	for _, contract := range manifest.Contracts {
		if contract.ID != "network-grant-schema" {
			continue
		}
		if contract.Version != NetworkGrantSchemaVersion {
			t.Fatalf("network-grant-schema version = %q, want %q", contract.Version, NetworkGrantSchemaVersion)
		}
		return
	}
	t.Fatal("compatibility manifest missing network-grant-schema")
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

func TestCurrentMatrixUsesInjectedReleaseVersions(t *testing.T) {
	restore := replaceReleaseVersions("1.2.3", "1.2.4", "1.2.5")
	defer restore()
	restoreDetector := replaceBuildInfoDetector("9.9.9")
	defer restoreDetector()

	matrix := CurrentMatrix()
	if matrix.GoModuleVersion != "1.2.3" || matrix.UIPackageVersion != "1.2.4" || matrix.RuntimeVersion != "1.2.5" {
		t.Fatalf("matrix versions = %#v", matrix)
	}
}

func TestCurrentMatrixFallsBackToBuildInfoVersion(t *testing.T) {
	restore := replaceReleaseVersions(devVersion, devVersion, devVersion)
	defer restore()
	restoreDetector := replaceBuildInfoDetector("0.7.0")
	defer restoreDetector()

	matrix := CurrentMatrix()
	if matrix.GoModuleVersion != "0.7.0" || matrix.UIPackageVersion != "0.7.0" || matrix.RuntimeVersion != "0.7.0" {
		t.Fatalf("matrix versions = %#v", matrix)
	}
}

func TestCurrentMatrixFallsBackToDevVersionWhenUnstamped(t *testing.T) {
	restore := replaceReleaseVersions("", "", "")
	defer restore()
	restoreDetector := replaceBuildInfoDetector("")
	defer restoreDetector()

	matrix := CurrentMatrix()
	if matrix.GoModuleVersion != devVersion || matrix.UIPackageVersion != devVersion || matrix.RuntimeVersion != devVersion {
		t.Fatalf("matrix versions = %#v", matrix)
	}
}

func TestNormalizeModuleVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "tag", in: "v1.2.3", want: "1.2.3"},
		{name: "prerelease", in: "v1.2.3-rc.1", want: "1.2.3-rc.1"},
		{name: "plain", in: "1.2.3", want: "1.2.3"},
		{name: "devel", in: "(devel)", want: ""},
		{name: "empty", in: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeModuleVersion(tc.in); got != tc.want {
				t.Fatalf("normalizeModuleVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
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

func replaceReleaseVersions(goVersion string, uiVersion string, runtimeVersion string) func() {
	oldGo := GoModuleVersion
	oldUI := UIPackageVersion
	oldRuntime := RuntimeVersion
	GoModuleVersion = goVersion
	UIPackageVersion = uiVersion
	RuntimeVersion = runtimeVersion
	return func() {
		GoModuleVersion = oldGo
		UIPackageVersion = oldUI
		RuntimeVersion = oldRuntime
	}
}

func replaceBuildInfoDetector(version string) func() {
	old := buildInfoModuleVersion
	buildInfoModuleVersion = func() string {
		return version
	}
	return func() {
		buildInfoModuleVersion = old
	}
}
