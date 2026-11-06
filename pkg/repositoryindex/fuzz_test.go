package repositoryindex

import (
	"encoding/json"
	"testing"
)

func FuzzDecodeRepositoryIndex(f *testing.F) {
	f.Add([]byte(`{"schema_version":"redevplugin.repository-index.v1","targets":[{"ecosystem":"redevplugin","host":"example","plugins":[{"slug":"example-plugin","path":".","manifest":"manifest.json","release":{"tag_template":"plugin-v{version}","package_asset_template":"plugin.redevplugin"}}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":"unknown"} true`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		index, err := Decode(raw)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(canonical); err != nil {
			t.Fatalf("accepted index cannot round trip: %v", err)
		}
	})
}
