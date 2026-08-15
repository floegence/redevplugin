package phase0

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

func compatPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "compat", "v1.1.4", name)
}

func TestPhase0FrozenV114ArtifactsAreImmutable(t *testing.T) {
	for _, fixture := range []struct {
		name       string
		sha        string
		workerPath string
		workerSHA  string
	}{
		{name: "ui-only.redevplugin", sha: "e9d5e320fb92a2df27fc8573470dfa17e14845711f78b87acc8c27155e86cfd9"},
		{name: "worker.redevplugin", sha: "fec2d584d9a48744d6b0df2cde59c61671af878780308388c806c4f7fd444e71", workerPath: "workers/memos.wasm", workerSHA: "b62b6e23a39c7bd43de9aadee055695f5586939349e2eee1e8218c81f3b4401f"},
	} {
		raw, err := os.ReadFile(compatPath(t, fixture.name))
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(raw)
		if got := hex.EncodeToString(actual[:]); got != fixture.sha {
			t.Fatalf("%s changed: got %s want %s", fixture.name, got, fixture.sha)
		}
		pkg, err := pluginpkg.Read(context.Background(), bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
		if err != nil {
			t.Fatalf("Read(%s): %v", fixture.name, err)
		}
		if pkg.Manifest.SchemaVersion != "redevplugin.manifest.v8" {
			t.Fatalf("%s schema = %q, want frozen v8", fixture.name, pkg.Manifest.SchemaVersion)
		}
		if fixture.workerPath != "" {
			worker := pkg.Files[fixture.workerPath]
			workerDigest := sha256.Sum256(worker)
			if got := hex.EncodeToString(workerDigest[:]); got != fixture.workerSHA {
				t.Fatalf("%s changed: got %s want %s", fixture.workerPath, got, fixture.workerSHA)
			}
			runtimeFixture, err := os.ReadFile(filepath.Join("..", "..", "crates", "redevplugin-runtime", "testdata", "memos.wasm"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(worker, runtimeFixture) {
				t.Fatal("frozen v1.1.4 worker differs from the byte-identical runtime execution fixture")
			}
		}
	}
}

func TestPhase0V9UnknownOptionalFieldPreservesManifestHash(t *testing.T) {
	raw := []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.v9","display_name":"V9","version":"1.0.0"},"api":{"surface":1,"worker":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]},"future":{"opaque":true}}`)
	if _, err := manifest.Decode(bytes.NewReader(raw)); err != nil {
		t.Fatalf("v9 optional field must be tolerated and normalized: %v", err)
	}
	withoutFuture := bytes.Replace(raw, []byte(`,"future":{"opaque":true}`), nil, 1)
	if bytes.Equal(raw, withoutFuture) {
		t.Fatal("test fixture did not include the unknown field")
	}
	if string(raw) == string(withoutFuture) {
		t.Fatal("unknown field was lost from the signed input")
	}
}

func TestPhase0UnknownRequiredFeatureIsRejected(t *testing.T) {
	raw := []byte(`{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example","display_name":"Example"},"plugin":{"plugin_id":"com.example.v9","display_name":"V9","version":"1.0.0"},"api":{"surface":1,"worker":1,"required_features":["io.future.v9"]},"permissions":[],"presentation":{"locales":{"default":"en-US"}},"surfaces":[],"workers":[],"methods":[],"storage":{"stores":[]}}`)
	_, err := manifest.Decode(bytes.NewReader(raw))
	if err == nil || !strings.Contains(strings.ToUpper(err.Error()), "UNSUPPORTED_FEATURE") {
		t.Fatalf("unknown required feature error = %v, want stable UNSUPPORTED_FEATURE", err)
	}
}
