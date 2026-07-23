package externalsource

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

type githubRoundTripFunc func(*http.Request) (*http.Response, error)

func (function githubRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type githubAPIRequestSnapshot struct {
	Scheme      string
	Host        string
	EscapedPath string
	Header      http.Header
}

func githubJSONResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestGitHubRESTReleaseClientResolvesLatestReleaseAndStableIdentity(t *testing.T) {
	const resolvedSHA = "0123456789abcdef0123456789abcdef01234567"
	var mu sync.Mutex
	var requests []githubAPIRequestSnapshot
	transport := githubRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		requests = append(requests, githubAPIRequestSnapshot{
			Scheme: request.URL.Scheme, Host: request.URL.Host, EscapedPath: request.URL.EscapedPath(), Header: request.Header.Clone(),
		})
		mu.Unlock()
		switch request.URL.EscapedPath() {
		case "/repos/example/plugin":
			return githubJSONResponse(`{"id":101,"name":"Plugin","owner":{"login":"Example"},"ignored_by_projection":true}`), nil
		case "/repos/example/plugin/releases/latest":
			return githubJSONResponse(`{
  "id":202,
  "tag_name":"v2.0.1",
  "target_commitish":"main",
  "assets":[
    {"id":303,"name":"plugin.redevplugin","browser_download_url":"https://github.com/example/plugin/releases/download/v2.0.1/plugin.redevplugin","size":4096,"content_type":"application/octet-stream"},
    {"id":304,"name":"checksums.txt","browser_download_url":"https://github.com/example/plugin/releases/download/v2.0.1/checksums.txt","size":128}
  ]
}`), nil
		case "/repos/example/plugin/commits/main":
			return githubJSONResponse(`{"sha":"` + resolvedSHA + `","commit":{"message":"release"}}`), nil
		default:
			t.Fatalf("unexpected GitHub API path %q", request.URL.EscapedPath())
			return nil, errors.New("unexpected request")
		}
	})
	client, err := NewGitHubRESTReleaseClient(GitHubRESTReleaseClientOptions{
		Token: "github_pat_example", UserAgent: "redeven-test/1.0", Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}

	release, err := client.LatestRelease(context.Background(), "Example", "Plugin")
	if err != nil {
		t.Fatal(err)
	}
	if release.RepositoryID != 101 || release.ReleaseID != 202 || release.Tag != "v2.0.1" || release.ResolvedCommitSHA != resolvedSHA {
		t.Fatalf("release identity = %#v", release)
	}
	if len(release.Assets) != 2 || release.Assets[0] != (GitHubReleaseAsset{
		AssetID: 303, Name: "plugin.redevplugin",
		DownloadURL: "https://github.com/example/plugin/releases/download/v2.0.1/plugin.redevplugin", Size: 4096,
	}) {
		t.Fatalf("release assets = %#v", release.Assets)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("GitHub API requests = %#v", requests)
	}
	for _, request := range requests {
		if request.Scheme != "https" || request.Host != "api.github.com" {
			t.Fatalf("GitHub API request escaped fixed origin: %#v", request)
		}
		if request.Header.Get("Authorization") != "Bearer github_pat_example" || request.Header.Get("User-Agent") != "redeven-test/1.0" ||
			request.Header.Get("Accept") != "application/vnd.github+json" || request.Header.Get("Accept-Encoding") != "identity" ||
			request.Header.Get("X-GitHub-Api-Version") != githubAPIVersion {
			t.Fatalf("GitHub API request headers = %#v", request.Header)
		}
	}
}

func TestGitHubRESTReleaseClientEscapesTagAndRevalidatesCommitSHA(t *testing.T) {
	const requestedSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var paths []string
	transport := githubRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		paths = append(paths, request.URL.EscapedPath())
		switch request.URL.EscapedPath() {
		case "/repos/example/plugin":
			return githubJSONResponse(`{"id":1,"name":"plugin","owner":{"login":"example"}}`), nil
		case "/repos/example/plugin/releases/tags/v2.0%2Fstable":
			return githubJSONResponse(`{"id":2,"tag_name":"v2.0/stable","target_commitish":"` + requestedSHA + `","assets":[]}`), nil
		case "/repos/example/plugin/commits/" + requestedSHA:
			return githubJSONResponse(`{"sha":"` + requestedSHA + `"}`), nil
		default:
			t.Fatalf("unexpected GitHub API path %q", request.URL.EscapedPath())
			return nil, errors.New("unexpected request")
		}
	})
	client, err := NewGitHubRESTReleaseClient(GitHubRESTReleaseClientOptions{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}

	release, err := client.ReleaseByTag(context.Background(), "example", "plugin", "v2.0/stable")
	if err != nil {
		t.Fatal(err)
	}
	if release.ResolvedCommitSHA != requestedSHA || len(paths) != 3 || paths[2] != "/repos/example/plugin/commits/"+requestedSHA {
		t.Fatalf("release=%#v paths=%#v", release, paths)
	}
}

func TestGitHubRESTReleaseClientRejectsRedirectWithoutCredentialLeak(t *testing.T) {
	var requests []*http.Request
	transport := githubRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Clone(request.Context()))
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {"https://attacker.example/steal"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
		}, nil
	})
	client, err := NewGitHubRESTReleaseClient(GitHubRESTReleaseClientOptions{Token: "github_pat_secret", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.LatestRelease(context.Background(), "example", "plugin")
	if CodeOf(err) != ErrorGitHubRelease {
		t.Fatalf("redirect error code=%q err=%v", CodeOf(err), err)
	}
	if len(requests) != 1 || requests[0].URL.Host != "api.github.com" || requests[0].Header.Get("Authorization") != "Bearer github_pat_secret" {
		t.Fatalf("redirect requests = %#v", requests)
	}
	if strings.Contains(err.Error(), "github_pat_secret") || strings.Contains(err.Error(), "attacker.example") {
		t.Fatalf("redirect error leaked credential or target: %v", err)
	}
}

func TestGitHubRESTReleaseClientBoundsAndClassifiesResponses(t *testing.T) {
	tests := []struct {
		name     string
		response func() *http.Response
	}{
		{
			name: "oversized",
			response: func() *http.Response {
				return githubJSONResponse(`{"padding":"` + strings.Repeat("x", githubAPIMaxResponseBytes) + `"}`)
			},
		},
		{
			name:     "trailing JSON",
			response: func() *http.Response { return githubJSONResponse(`{"id":1} {"id":2}`) },
		},
		{
			name:     "duplicate field",
			response: func() *http.Response { return githubJSONResponse(`{"id":1,"id":2}`) },
		},
		{
			name: "excessive nesting",
			response: func() *http.Response {
				return githubJSONResponse(strings.Repeat(`{"nested":`, githubAPIMaxJSONDepth+1) + `null` + strings.Repeat(`}`, githubAPIMaxJSONDepth+1))
			},
		},
		{
			name: "invalid content type",
			response: func() *http.Response {
				response := githubJSONResponse(`{"id":1}`)
				response.Header.Set("Content-Type", "text/html")
				return response
			},
		},
		{
			name: "compressed",
			response: func() *http.Response {
				response := githubJSONResponse(`{"id":1}`)
				response.Header.Set("Content-Encoding", "gzip")
				return response
			},
		},
		{
			name: "rate limited",
			response: func() *http.Response {
				response := githubJSONResponse(`{"message":"rate limited","token":"must-not-surface"}`)
				response.StatusCode = http.StatusTooManyRequests
				return response
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewGitHubRESTReleaseClient(GitHubRESTReleaseClientOptions{Transport: githubRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return tt.response(), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.LatestRelease(context.Background(), "example", "plugin")
			if CodeOf(err) != ErrorGitHubRelease {
				t.Fatalf("error code=%q err=%v", CodeOf(err), err)
			}
			if strings.Contains(err.Error(), "must-not-surface") {
				t.Fatalf("error leaked response body: %v", err)
			}
		})
	}
}

func TestGitHubRESTReleaseClientRejectsIdentityDriftAndUnsafeOptions(t *testing.T) {
	tests := []GitHubRESTReleaseClientOptions{
		{Token: " token"},
		{Token: "token\nvalue"},
		{UserAgent: " agent"},
		{UserAgent: "agent\r\nheader"},
	}
	for _, options := range tests {
		if _, err := NewGitHubRESTReleaseClient(options); CodeOf(err) != ErrorInvalidSource {
			t.Fatalf("options %#v: code=%q err=%v", options, CodeOf(err), err)
		}
	}

	const requestedSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const differentSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	transport := githubRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.EscapedPath() {
		case "/repos/example/plugin":
			return githubJSONResponse(`{"id":1,"name":"plugin","owner":{"login":"example"}}`), nil
		case "/repos/example/plugin/releases/latest":
			return githubJSONResponse(`{"id":2,"tag_name":"v1","target_commitish":"` + requestedSHA + `","assets":[]}`), nil
		case "/repos/example/plugin/commits/" + requestedSHA:
			return githubJSONResponse(`{"sha":"` + differentSHA + `"}`), nil
		default:
			return nil, errors.New("unexpected request")
		}
	})
	client, err := NewGitHubRESTReleaseClient(GitHubRESTReleaseClientOptions{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.LatestRelease(context.Background(), "example", "plugin"); CodeOf(err) != ErrorGitHubRelease {
		t.Fatalf("commit drift code=%q err=%v", CodeOf(err), err)
	}
	if _, err := client.LatestRelease(context.Background(), "../escape", "plugin"); CodeOf(err) != ErrorInvalidSource {
		t.Fatalf("invalid repository code=%q err=%v", CodeOf(err), err)
	}
}

func TestGitHubRESTReleaseClientDisablesProxyAndProvidesResolverConstructor(t *testing.T) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = http.ProxyFromEnvironment
	base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS10}
	client, err := NewGitHubRESTReleaseClient(GitHubRESTReleaseClientOptions{Transport: base})
	if err != nil {
		t.Fatal(err)
	}
	configured, ok := client.http.Transport.(*http.Transport)
	if !ok || configured == base || configured.Proxy != nil || configured.TLSClientConfig == nil || configured.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("configured transport = %#v", client.http.Transport)
	}
	if base.Proxy == nil || base.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatal("constructor mutated the caller-owned transport")
	}

	fetcher, _ := newTestFetcher(t, staticResolver{"objects.githubusercontent.com": {netip.MustParseAddr("1.1.1.1")}})
	resolver, err := NewGitHubRESTReleaseResolver(GitHubRESTReleaseClientOptions{Transport: githubRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	})}, fetcher)
	if err != nil {
		t.Fatal(err)
	}
	if resolver == nil || resolver.fetcher != fetcher {
		t.Fatalf("resolver = %#v", resolver)
	}
	if _, ok := resolver.client.(*GitHubRESTReleaseClient); !ok {
		t.Fatalf("resolver client = %T", resolver.client)
	}
}
