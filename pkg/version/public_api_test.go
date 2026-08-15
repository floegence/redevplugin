package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPublicAPICatalogDoesNotExposeInternalContractVersions(t *testing.T) {
	catalog := CurrentPublicAPICatalog()
	if catalog.SchemaVersion != "redevplugin.public_api.v1" || len(catalog.SurfaceAPIMajors) != 1 || catalog.SurfaceAPIMajors[0] != 1 || len(catalog.WorkerAPIMajors) != 1 || catalog.WorkerAPIMajors[0] != 1 {
		t.Fatalf("unexpected public API catalog: %#v", catalog)
	}
	limits := catalog.MinimumResources
	if limits.ControlResponseBytes != 64<<10 || limits.IOChunkBytes != 64<<10 || limits.OpenFiles < 64 || limits.OpenConnections < 32 || limits.OpenWatches < 8 {
		t.Fatalf("public resource guarantees regressed: %#v", catalog)
	}
}

func TestPublicAPICatalogMatchesPublishedMachineContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", "public-api-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var published PublicAPICatalog
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(published, CurrentPublicAPICatalog()) {
		t.Fatalf("public API catalog drifted: published=%#v current=%#v", published, CurrentPublicAPICatalog())
	}
}
