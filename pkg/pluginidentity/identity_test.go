package pluginidentity

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGitHubIdentityBindsRepositoryAndSlug(t *testing.T) {
	id, err := GitHub(1289352675, "mind-map")
	if err != nil || id.PublisherID != "github.repo.1289352675" || id.PluginID != "github.repo.1289352675.mind-map" {
		t.Fatalf("identity: %+v %v", id, err)
	}
	if err := ValidateGitHub(1289352675, id.PublisherID, id.PluginID); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		repo        int64
		pub, plugin string
	}{
		{42, id.PublisherID, id.PluginID}, {1289352675, "com.redeven.official", id.PluginID},
		{1289352675, id.PublisherID, "github.repo.12893526750.mind-map"}, {1289352675, id.PublisherID, "github.repo.01289352675.mind-map"},
		{1289352675, id.PublisherID, "github.repo.1289352675.foo.bar"},
	} {
		if ValidateGitHub(v.repo, v.pub, v.plugin) == nil {
			t.Fatalf("accepted %+v", v)
		}
	}
}
func TestGitHubIdentityRejectsInvalidInputs(t *testing.T) {
	for _, n := range []int64{0, -1, 9007199254740992} {
		if _, err := GitHub(n, "plugin"); err == nil {
			t.Fatal(n)
		}
	}
	for _, s := range []string{"", "A", "-bad", "bad-", "a..b", "a_b", "a.b", "../a", " a", "a\n"} {
		if _, err := GitHub(1, s); err == nil {
			t.Fatal(s)
		}
	}
}

func TestCrossLanguageFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../spec/plugin/repository-identity-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	type example struct {
		RepositoryID int64  `json:"repository_id"`
		PublisherID  string `json:"publisher_id"`
		PluginID     string `json:"plugin_id"`
		Slug         string `json:"slug"`
	}
	var fixtures struct {
		Valid   []example `json:"valid"`
		Invalid []example `json:"invalid"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixtures.Valid {
		id, err := GitHub(v.RepositoryID, v.Slug)
		if err != nil || id.PluginID != v.PluginID || id.PublisherID != v.PublisherID {
			t.Fatal(v, err)
		}
	}
	for _, v := range fixtures.Invalid {
		if ValidateGitHub(v.RepositoryID, v.PublisherID, v.PluginID) == nil {
			t.Fatal(v)
		}
	}
}

func TestDeclarationNeverProvesSourceOwnership(t *testing.T) {
	for _, pair := range [][2]string{{"local.generated", "local.example"}, {"github.repo.42", "github.repo.42.example"}} {
		if err := ValidateDeclaration(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{"github.repo.042", "github.repo.042.example"}, {"github.repo.42", "github.repo.43.example"}, {"local.generated", "github.repo.42.example"}, {"github.repo.42", "local.example"}} {
		if ValidateDeclaration(pair[0], pair[1]) == nil {
			t.Fatalf("accepted inconsistent declaration: %v", pair)
		}
	}
}
