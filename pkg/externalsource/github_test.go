package externalsource

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
)

type fakeGitHubClient struct {
	release      GitHubRelease
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
		Tag:               "v1.2.3",
		Assets: []GitHubReleaseAsset{
			{AssetID: 1, Name: "checksums.txt", DownloadURL: "https://objects.githubusercontent.com/checksums", Size: 10},
			{AssetID: 303, Name: "plugin.redevplugin", DownloadURL: "https://objects.githubusercontent.com/plugin?token=secret", Size: int64(len(content))},
		},
	}}
	resolver, err := NewGitHubReleaseResolver(client, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.ResolvePackage(context.Background(), GitHubRepositorySource{RepositoryURL: "https://GitHub.com/Example/Plugin", Tag: "v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.stage.Remove(result.Fetch.Artifact) })
	if client.byTagCalls != 1 || client.latestCalls != 0 || client.requestedTag != "v1.2.3" {
		t.Fatalf("client calls: latest=%d byTag=%d tag=%q", client.latestCalls, client.byTagCalls, client.requestedTag)
	}
	if result.RepositoryURL != "https://github.com/example/plugin" || result.RepositoryID != 101 || result.ReleaseID != 202 || result.AssetID != 303 {
		t.Fatalf("resolved identity = %#v", result)
	}
	if strings.Contains(result.Fetch.Source, "secret") || strings.Contains(result.Fetch.Final, "secret") {
		t.Fatalf("resolved result leaked signed query: %#v", result.Fetch)
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
		Tag:               "v1",
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
