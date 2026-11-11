package host

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

func TestEverydayCategorySurvivesPackageInstallAndRestart(t *testing.T) {
	for _, category := range []string{"games", "lifestyle", "health", "education", "finance", "media", ""} {
		t.Run(category, func(t *testing.T) {
			dir := t.TempDir()
			raw := lifecycleManifestJSON("1.0.0", "Everyday application")
			if category != "" {
				raw = strings.Replace(raw, `"presentation": {`, `"presentation": {"category":"`+category+`",`, 1)
			}
			writeFile(t, filepath.Join(dir, "manifest.json"), raw)
			writeSurfaceFixture(t, dir, "Everyday application")
			var archive bytes.Buffer
			pkg, err := pluginpkg.BuildFromDir(hostTestContext(), dir, &archive, pluginpkg.DefaultReadLimits())
			if err != nil {
				t.Fatal(err)
			}
			assets, err := pluginpkg.NewFileAssetStore(filepath.Join(t.TempDir(), "assets"))
			if err != nil {
				t.Fatal(err)
			}
			options := testHostOptions{stateRoot: t.TempDir(), assets: assets}
			h, _, _ := newTestHostWithOptions(t, options)
			record, err := ImportLocalPackageBytes(hostTestContext(), h, nextTestPluginInstanceID(t), archive.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			for restart := range 2 {
				inventory, err := h.ListPluginInventory(hostTestContext())
				if err != nil || len(inventory) != 1 {
					t.Fatalf("inventory: %+v %v", inventory, err)
				}
				current := inventory[0].Plugin
				if current.PluginInstanceID != record.PluginInstanceID || current.PackageHash != pkg.PackageHash || current.CanonicalManifest != record.CanonicalManifest {
					t.Fatal("installed package identity changed")
				}
				if current.Manifest.Presentation.Category != manifest.PluginCategory(category) || current.Manifest.PresentationCatalog().Category.Effective() != manifest.PluginCategory(category).Effective() {
					t.Fatalf("installed category changed: %+v", current.Manifest.Presentation)
				}
				if restart == 0 {
					if err := h.Close(); err != nil {
						t.Fatal(err)
					}
					h, _, _ = newTestHostWithOptions(t, options)
				}
			}
		})
	}
}
