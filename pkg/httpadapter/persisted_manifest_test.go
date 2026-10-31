package httpadapter

import (
	"encoding/json"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestStoredManifestInventoryDoesNotInventWebAuthority(t *testing.T) {
	old := manifest.Manifest{Surfaces: []manifest.SurfaceSpec{{SurfaceID: "old", Kind: manifest.SurfaceView, Label: "Old", Entry: "ui/index.html"}}}
	current := manifest.Manifest{Surfaces: []manifest.SurfaceSpec{{SurfaceID: "current", Kind: manifest.SurfaceView, Label: "Current", Entry: "ui/index.html", Web: manifest.SurfaceWebSpec{Root: "ui"}}}}
	records := []host.PluginInventoryRecord{
		{Plugin: registry.PluginRecord{PluginInstanceID: "old", Manifest: old}, ActionState: host.PluginActionState{CanUninstall: true, BlockedReason: host.PluginActionBlockedIncompatible}},
		{Plugin: registry.PluginRecord{PluginInstanceID: "current", Manifest: current, VersionHistory: []registry.PluginVersion{{Manifest: old}}}, ActionState: host.PluginActionState{CanOpen: true}},
	}
	projected, err := publicPluginInventory(records)
	if err != nil {
		t.Fatal(err)
	}
	if projected[0].Manifest.Surfaces[0].Web != nil || projected[1].VersionHistory[0].Manifest.Surfaces[0].Web != nil {
		t.Fatal("invented retained Web declaration")
	}
	if projected[1].Manifest.Surfaces[0].Web == nil || projected[1].Manifest.Surfaces[0].Web.Root != "ui" {
		t.Fatal("current Web authority lost")
	}
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	var value []map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	surface := value[0]["manifest"].(map[string]any)["surfaces"].([]any)[0].(map[string]any)
	if _, exists := surface["web"]; exists {
		t.Fatal("retained inventory emits synthetic Web authority")
	}
}
