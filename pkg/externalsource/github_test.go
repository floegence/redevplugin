package externalsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
)

type fakeGitHubClient struct {
	release      GitHubRelease
	afterRelease *GitHubRelease
	afterError   error
	latestCalls  int
	byTagCalls   int
	requestedTag string
}

func (client *fakeGitHubClient) LatestRelease(context.Context, string, string) (GitHubRelease, error) {
	client.latestCalls++
	return client.release, nil
}

func (client *fakeGitHubClient) ReleaseByTag(_ context.Context, _, _, tag string) (GitHubRelease, error) {
	client.byTagCalls++
	client.requestedTag = tag
	if client.byTagCalls > 1 {
		if client.afterError != nil {
			return GitHubRelease{}, client.afterError
		}
		if client.afterRelease != nil {
			return *client.afterRelease, nil
		}
	}
	return client.release, nil
}

func TestGitHubReleaseResolverFetchesUniquePackageAsset(t *testing.T) {
	content := "release-package"
	fetcher, _ := newTestFetcher(t, staticResolver{"objects.githubusercontent.com": {netip.MustParseAddr("1.1.1.1")}})
	fetcher.roundTrip = func(_ context.Context, locator PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		if got := locator.requestURL().Query().Get("token"); got != "secret" {
			t.Fatalf("signed query token = %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(content)), ContentLength: int64(len(content))}, nil
	}
	client := &fakeGitHubClient{release: GitHubRelease{
		ResolvedCommitSHA: "0123456789abcdef0123456789abcdef01234567",
		RepositoryID:      101,
		ReleaseID:         202,
		Tag:               "plugin-v1.2.3",
		Assets: []GitHubReleaseAsset{
			{AssetID: 1, Name: "checksums.txt", DownloadURL: "https://objects.githubusercontent.com/checksums", Size: 10},
			{AssetID: 303, Name: "plugin.redevplugin", DownloadURL: "https://objects.githubusercontent.com/plugin?token=secret", Size: int64(len(content))},
		},
	}}
	resolver, err := NewGitHubReleaseResolver(client, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.ResolvePackage(context.Background(), GitHubRepositorySource{RepositoryURL: "https://GitHub.com/Example/Plugin", Tag: "plugin-v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.stage.Remove(result.Fetch.Artifact) })
	if client.byTagCalls != 2 || client.latestCalls != 0 || client.requestedTag != "plugin-v1.2.3" {
		t.Fatalf("client calls: latest=%d byTag=%d tag=%q", client.latestCalls, client.byTagCalls, client.requestedTag)
	}
	if result.RepositoryURL != "https://github.com/example/plugin" || result.RepositoryID != 101 || result.ReleaseID != 202 || result.AssetID != 303 {
		t.Fatalf("resolved identity = %#v", result)
	}
	if strings.Contains(result.Fetch.Source, "secret") || strings.Contains(result.Fetch.Final, "secret") {
		t.Fatalf("resolved result leaked signed query: %#v", result.Fetch)
	}
}

func TestGitHubReleaseResolverRejectsIdentityChangesDuringDownload(t *testing.T) {
	for _, field := range []string{"repository", "release", "commit", "tag", "asset", "name", "url", "size", "missing", "duplicate", "unavailable"} {
		t.Run(field, func(t *testing.T) {
			fetcher, directory := newTestFetcher(t, staticResolver{"objects.githubusercontent.com": {netip.MustParseAddr("1.1.1.1")}})
			client := &fakeGitHubClient{release: GitHubRelease{RepositoryID: 1, ReleaseID: 2, Tag: "plugin-v1.0.0", ResolvedCommitSHA: strings.Repeat("a", 40), Assets: []GitHubReleaseAsset{{AssetID: 3, Name: "plugin.redevplugin", DownloadURL: "https://objects.githubusercontent.com/plugin", Size: 7}}}}
			fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
				next := client.release
				next.Assets = append([]GitHubReleaseAsset(nil), next.Assets...)
				switch field {
				case "repository":
					next.RepositoryID++
				case "release":
					next.ReleaseID++
				case "commit":
					next.ResolvedCommitSHA = strings.Repeat("b", 40)
				case "tag":
					next.Tag = "plugin-v1.1.0"
				case "asset":
					next.Assets[0].AssetID++
				case "name":
					next.Assets[0].Name = "changed.redevplugin"
				case "url":
					next.Assets[0].DownloadURL += "-changed"
				case "size":
					next.Assets[0].Size++
				case "missing":
					next.Assets = nil
				case "duplicate":
					next.Assets = append(next.Assets, next.Assets[0])
				case "unavailable":
					client.afterError = errors.New("release disappeared")
				}
				client.afterRelease = &next
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("package")), ContentLength: 7}, nil
			}
			resolver, err := NewGitHubReleaseResolver(client, fetcher)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolvePackage(context.Background(), GitHubRepositorySource{RepositoryURL: "https://github.com/example/plugin"}); err == nil {
				t.Fatal("changed release metadata accepted")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected download retained staged bytes: %v %v", entries, err)
			}
		})
	}
}

func TestGitHubReleaseResolverRejectsInvalidRepositoryAndAssetSelection(t *testing.T) {
	invalidRepositories := []string{
		"http://github.com/example/plugin",
		"https://github.example/example/plugin",
		"https://github.com/example/plugin.git",
		"https://github.com/example/plugin/tree/main",
		"https://user@github.com/example/plugin",
		"https://github.com/example/plugin?token=secret",
	}
	for _, repositoryURL := range invalidRepositories {
		_, _, _, err := parseGitHubRepositoryURL(repositoryURL)
		if CodeOf(err) != ErrorInvalidSource {
			t.Fatalf("repository %q: code=%q err=%v", repositoryURL, CodeOf(err), err)
		}
	}

	_, err := uniquePluginAsset(nil, "https://github.com/example/plugin")
	if CodeOf(err) != ErrorGitHubAssetMissing {
		t.Fatalf("missing code=%q err=%v", CodeOf(err), err)
	}
	_, err = uniquePluginAsset([]GitHubReleaseAsset{
		{AssetID: 1, Name: "one.redevplugin", DownloadURL: "https://example.com/one", Size: 1},
		{AssetID: 2, Name: "two.REDEVPLUGIN", DownloadURL: "https://example.com/two", Size: 1},
	}, "https://github.com/example/plugin")
	if CodeOf(err) != ErrorGitHubAssetAmbiguous {
		t.Fatalf("ambiguous code=%q err=%v", CodeOf(err), err)
	}
}

func TestGitHubReleaseResolverRemovesSizeMismatch(t *testing.T) {
	fetcher, directory := newTestFetcher(t, staticResolver{"objects.githubusercontent.com": {netip.MustParseAddr("1.1.1.1")}})
	fetcher.roundTrip = func(_ context.Context, _ PackageURL, _ []netip.Addr, _ http.Header) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("actual")), ContentLength: -1}, nil
	}
	client := &fakeGitHubClient{release: GitHubRelease{
		ResolvedCommitSHA: "0123456789abcdef0123456789abcdef01234567",
		RepositoryID:      1,
		ReleaseID:         2,
		Tag:               "plugin-v1.0.0",
		Assets: []GitHubReleaseAsset{{
			AssetID: 3, Name: "plugin.redevplugin", DownloadURL: "https://objects.githubusercontent.com/plugin", Size: 100,
		}},
	}}
	resolver, err := NewGitHubReleaseResolver(client, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.ResolvePackage(context.Background(), GitHubRepositorySource{RepositoryURL: "https://github.com/example/plugin"})
	if CodeOf(err) != ErrorStageIntegrity {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("stage directory %q entries=%v err=%v", directory, entries, readErr)
	}
}

func (client *fakeGitHubClient) RepositoryIndex(context.Context, string, string) (repositoryindex.Index, error) {
	return repositoryindex.Index{SchemaVersion: repositoryindex.SchemaVersion, Targets: []repositoryindex.Target{{Ecosystem: "redevplugin", Host: "example", Plugins: []repositoryindex.Plugin{{PluginID: "example.plugin", Path: ".", Manifest: "manifest.json", Release: &repositoryindex.Release{TagTemplate: "plugin-v{version}", PackageAssetTemplate: "plugin.redevplugin"}}}}}}, nil
}
func (client *fakeGitHubClient) ReleaseTags(context.Context, string, string) ([]GitHubReleaseTag, error) {
	return []GitHubReleaseTag{{Tag: client.release.Tag}}, nil
}

func TestRepositoryPluginSelectionIsUnambiguousAndVersionOrdered(t *testing.T) {
	index, _ := (&fakeGitHubClient{}).RepositoryIndex(context.Background(), "", "")
	plugin := index.Targets[0].Plugins[0]
	tags := []GitHubReleaseTag{{Tag: "other-v90.0.0"}, {Tag: "plugin-v1.9.0"}, {Tag: "plugin-v1.10.0"}, {Tag: "plugin-v2.0.0-rc.1"}, {Tag: "plugin-v3.0.0", Draft: true}, {Tag: "plugin-v4.0.0", Prerelease: true}}
	tag, err := selectPluginTag(plugin, tags)
	if err != nil || tag != "plugin-v1.10.0" {
		t.Fatalf("selection: %s %v", tag, err)
	}
	other := plugin
	other.PluginID = "example.second"
	other.Path = "second"
	other.Release = &repositoryindex.Release{TagTemplate: "second-v{version}", PackageAssetTemplate: "plugin.redevplugin"}
	index.Targets[0].Plugins = append(index.Targets[0].Plugins, other)
	if _, err := selectRepositoryPlugin(index, "example", ""); err == nil {
		t.Fatal("ambiguous repository selected arbitrary plugin")
	}
	selected, err := selectRepositoryPlugin(index, "example", "example.second")
	if err != nil || selected.PluginID != other.PluginID {
		t.Fatalf("explicit selection: %+v %v", selected, err)
	}
}
