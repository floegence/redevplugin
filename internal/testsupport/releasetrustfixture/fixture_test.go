package releasetrustfixture

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/releasetrust"
)

type noopFence struct{}

func (noopFence) TeardownSourceTrust(context.Context, releasetrust.SourceFenceRequest) error {
	return nil
}

func TestFixtureVerifiesReleaseAndAuthorizesActivation(t *testing.T) {
	packageBytes := buildPackage(t)
	fixture, err := New(packageBytes, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.ServiceSet.BindFenceCoordinator(noopFence{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := fixture.ServiceSet.PrepareRelease(context.Background(), fixture.Identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := fixture.ServiceSet.VerifyReleaseMetadata(
		context.Background(), prepared, fixture.MetadataBytes, fixture.MetadataSignature,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixture.ServiceSet.VerifyPackage(context.Background(), metadata, fixture.PackageSignature)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := verified.AuthorizeActivation()
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.ServiceSet.ValidateActivationLease(lease); err != nil {
		t.Fatal(err)
	}
}

func buildPackage(t *testing.T) []byte {
	t.Helper()
	directory := t.TempDir()
	manifest := `{
  "schema_version": "redevplugin.manifest.v5",
  "publisher": {"publisher_id": "fixture.publisher", "display_name": "Fixture"},
  "plugin": {
    "plugin_id": "fixture.plugin",
    "display_name": "Fixture",
    "version": "1.0.0",
    "api_version": "plugin-v1",
    "min_runtime_version": "0.1.0",
    "ui_protocol_version": "plugin-ui-v5"
  },
  "surfaces": [
    {"surface_id": "fixture.view", "kind": "view", "label": "Fixture", "entry": "ui/index.html"}
  ]
}`
	if err := os.MkdirAll(filepath.Join(directory, "ui", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ui", "index.html"), []byte(`<!doctype html><title>Fixture</title><script type="text/redevplugin-worker" src="assets/app.js"></script>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ui", "assets", "app.js"), []byte("void 0;"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), directory, &buffer, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
