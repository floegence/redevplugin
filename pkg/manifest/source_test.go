package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
)

func TestAuthorSourceCompilesWithoutMutatingAuthoredIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../examples/plugins/weather/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	source, err := AuthorSource(raw, "weather")
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), source...)
	if bytes.Contains(source, []byte("publisher_id")) || bytes.Contains(source, []byte("plugin_id")) {
		t.Fatal("source contains generated identity")
	}
	for _, repo := range []int64{42, 43} {
		identity, err := pluginidentity.GitHub(repo, "weather")
		if err != nil {
			t.Fatal(err)
		}
		m, canonical, err := CompileSource(source, identity)
		if err != nil {
			t.Fatal(err)
		}
		if m.PluginID() != identity.PluginID || m.Publisher.PublisherID != identity.PublisherID {
			t.Fatal(m)
		}
		if _, _, err := DecodeCanonical(bytes.NewReader(canonical)); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(source, original) {
		t.Fatal("source changed")
	}
	if _, _, err := DecodeCanonical(bytes.NewReader(source)); err == nil {
		t.Fatal("source admitted as installable manifest")
	}
	m, _, err := DecodeAuthorCanonical(bytes.NewReader(source))
	if err != nil || m.PluginID() != "weather" || m.Publisher.PublisherID != "local.generated" {
		t.Fatal(m, err)
	}
}

func TestAuthorSourceRejectsAmbiguousAndAuthoredRepositoryIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../examples/plugins/weather/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	source, err := AuthorSource(raw, "weather")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(d map[string]any) { d["plugin"].(map[string]any)["slug"] = "github.repo.42.weather" },
		func(d map[string]any) { d["plugin"].(map[string]any)["plugin_id"] = "github.repo.42.weather" },
		func(d map[string]any) { d["publisher"].(map[string]any)["publisher_id"] = "github.repo.42" },
		func(d map[string]any) { d["plugin"].(map[string]any)["slug"] = "weather\n" },
	} {
		var doc map[string]any
		if err := json.Unmarshal(source, &doc); err != nil {
			t.Fatal(err)
		}
		change(doc)
		changed, _ := json.Marshal(doc)
		if _, _, err := DecodeAuthorCanonical(bytes.NewReader(changed)); err == nil {
			t.Fatal("invalid source accepted", string(changed))
		}
	}
	duplicate := bytes.Replace(source, []byte(`"slug":"weather"`), []byte(`"slug":"weather","slug":"other"`), 1)
	if bytes.Equal(duplicate, source) {
		t.Fatal("duplicate fixture failed")
	}
	if _, _, err := DecodeAuthorCanonical(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate source accepted")
	}
}
