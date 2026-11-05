package releasepublisher

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/releaseprojection"
)

func publisherPackage(t *testing.T, withIcon bool) (string, pluginpkg.Package, []byte) {
	t.Helper()
	root := t.TempDir()
	icon := ""
	var imageBytes bytes.Buffer
	if withIcon {
		img := image.NewRGBA(image.Rect(0, 0, 16, 16))
		img.Set(0, 0, color.RGBA{R: 255, A: 255})
		if err := png.Encode(&imageBytes, img); err != nil {
			t.Fatal(err)
		}
		icon = `,"icon":{"path":"assets/icon.png"}`
		if err := os.MkdirAll(filepath.Join(root, "assets"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "assets/icon.png"), imageBytes.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `{"schema_version":"redevplugin.manifest.v9","publisher":{"publisher_id":"example"},"plugin":{"plugin_id":"example.open","display_name":"Open","version":"1.0.0"},"api":{"major":1,"optional_features":[]},"permissions":[],"presentation":{"locales":{"default":"en-US"}` + icon + `},"surfaces":[],"workers":[],"methods":[]}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(context.Background(), root, &archive, pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plugin.redevplugin")
	if err = os.WriteFile(path, archive.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return path, pkg, imageBytes.Bytes()
}
func TestInspectOrdinaryPackageBindsIdentityAndContent(t *testing.T) {
	path, pkg, _ := publisherPackage(t, false)
	got, err := InspectPackage(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.PluginID != "example.open" || got.Version != "1.0.0" || got.PackageSHA256 != pkg.PackageHash || got.ManifestSHA256 != pkg.ManifestHash || got.EntriesSHA256 != pkg.EntriesHash || got.SecuritySummary.SummarySHA256 == "" || got.ContractSetSHA256 == "" {
		t.Fatalf("inspection: %+v", got)
	}
	if got.PresentationIcon != nil {
		t.Fatal("invented icon")
	}
	if _, err := ExtractPresentationIcon(context.Background(), path, filepath.Join(t.TempDir(), "icon.png")); !errors.Is(err, pluginpkg.ErrPresentationIconUnavailable) {
		t.Fatal(err)
	}
}
func TestExtractPackageIconUsesExactBytesAndNeverOverwrites(t *testing.T) {
	path, _, expected := publisherPackage(t, true)
	out := filepath.Join(t.TempDir(), "icon.png")
	icon, err := ExtractPresentationIcon(context.Background(), path, out)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("icon changed", err)
	}
	if icon.SchemaVersion != PresentationIconEvidenceSchemaVersion || icon.Width != 16 || icon.Height != 16 || icon.SHA256 == "" {
		t.Fatalf("icon: %+v", icon)
	}
	if _, err := ExtractPresentationIcon(context.Background(), path, out); !errors.Is(err, ErrPresentationIconOutputExists) {
		t.Fatal("overwrote output", err)
	}
}

func TestPackageInspectionUsesHostScopedWorkerPermissions(t *testing.T) {
	m := manifest.Manifest{Permissions: []manifest.PermissionID{manifest.PermissionNetworkClient}, Methods: []manifest.MethodSpec{{Method: "worker.read", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "worker"}, Permissions: []manifest.PermissionID{}}}}
	expected, err := releaseprojection.BuildExternalPackageSecuritySummaryFromContracts(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := releaseSecuritySummary(m, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if actual.SummarySHA256 != expected.SummarySHA256 {
		t.Fatal("publisher and Host disagree on scoped worker permissions")
	}
}
