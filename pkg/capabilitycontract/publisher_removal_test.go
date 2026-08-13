package capabilitycontract

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIndependentCapabilityPublisherArtifactsAreRemoved(t *testing.T) {
	root := capabilityContractRepositoryRoot(t)
	for _, path := range []string{
		"cmd/redevplugin/host_capability.go",
		"spec/plugin/host-capability-manifest-v1.schema.json",
		"spec/plugin/host-capability-signature-v1.schema.json",
		"spec/plugin/host-capability-compatibility-v1.schema.json",
		"spec/plugin/host-capability-notices-v1.schema.json",
	} {
		if _, err := os.Stat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retired capability publisher artifact %s still exists: %v", path, err)
		}
	}

	for _, path := range []string{"types.go", "artifact.go", "files.go", "registry.go"} {
		raw, err := os.ReadFile(filepath.Join(root, "pkg", "capabilitycontract", path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range []string{
			"type Bundle struct", "type PreparedBundle struct", "type TrustedKey struct",
			"type Manifest struct", "type Compatibility struct", "type SignatureEnvelope struct",
			"func Build(", "func Prepare(", "func Finalize(", "func Verify(", "func ReadBundle(",
		} {
			if strings.Contains(string(raw), retired) {
				t.Fatalf("%s retains independent capability publisher API %q", path, retired)
			}
		}
	}
}

func capabilityContractRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
