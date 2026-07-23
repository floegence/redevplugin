package externalsource

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	githubAPIOrigin           = "https://api.github.com"
	githubAPIMaxResponseBytes = 8 << 20
	githubAPIMaxAssets        = 1000
	githubAPIMaxJSONDepth     = 32
	githubAPIMaxJSONItems     = 10_000
	githubAPIDefaultUserAgent = "redevplugin"
	githubAPIVersion          = "2022-11-28"
)

// GitHubRESTReleaseClientOptions configures the public GitHub REST client.
// Transport is injectable for deterministic testing, but every request URL
// remains fixed to https://api.github.com. Injected *http.Transport values are
// cloned with proxy use disabled.
type GitHubRESTReleaseClientOptions struct {
	Token     string
	UserAgent string
	Transport http.RoundTripper
}

// GitHubRESTReleaseClient resolves GitHub release and commit identities through
// the fixed public GitHub REST origin. It never follows redirects or uses an
// ambient HTTP proxy.
type GitHubRESTReleaseClient struct {
	http      *http.Client
	token     string
	userAgent string
}

var _ GitHubReleaseClient = (*GitHubRESTReleaseClient)(nil)

// NewGitHubRESTReleaseClient creates a host-neutral concrete implementation of
// GitHubReleaseClient. Empty Token enables public unauthenticated requests.
func NewGitHubRESTReleaseClient(options GitHubRESTReleaseClientOptions) (*GitHubRESTReleaseClient, error) {
	token := options.Token
	if len(token) > 4096 || strings.TrimSpace(token) != token || containsControl(token) {
		return nil, invalidSource("new_github_rest_client", "GitHub token is invalid")
	}
	userAgent := options.UserAgent
	if userAgent == "" {
		userAgent = githubAPIDefaultUserAgent
	}
	if len(userAgent) > 256 || strings.TrimSpace(userAgent) != userAgent || containsControl(userAgent) {
		return nil, invalidSource("new_github_rest_client", "GitHub user agent is invalid")
	}
	transport := options.Transport
	if transport == nil {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, invalidSource("new_github_rest_client", "default HTTP transport is unavailable")
		}
		transport = base
	}
	if base, ok := transport.(*http.Transport); ok {
		configured := base.Clone()
		configured.Proxy = nil
		if configured.TLSClientConfig == nil {
			configured.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			configured.TLSClientConfig = configured.TLSClientConfig.Clone()
			if configured.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				configured.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		transport = configured
	}
	return &GitHubRESTReleaseClient{
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("GitHub API redirects are disabled")
			},
		},
		token: token, userAgent: userAgent,
	}, nil
}

// NewGitHubRESTReleaseResolver wires the concrete REST client into the existing
// release asset resolver. Hosts supply only credentials, egress transport, and
// the shared hardened package fetcher.
func NewGitHubRESTReleaseResolver(options GitHubRESTReleaseClientOptions, fetcher *Fetcher) (*GitHubReleaseResolver, error) {
	client, err := NewGitHubRESTReleaseClient(options)
	if err != nil {
		return nil, err
	}
	return NewGitHubReleaseResolver(client, fetcher)
}

func (client *GitHubRESTReleaseClient) LatestRelease(ctx context.Context, owner, repository string) (GitHubRelease, error) {
	return client.resolveRelease(ctx, owner, repository, "", true)
}

func (client *GitHubRESTReleaseClient) ReleaseByTag(ctx context.Context, owner, repository, tag string) (GitHubRelease, error) {
	if tag == "" || len(tag) > 255 || strings.TrimSpace(tag) != tag || containsControl(tag) {
		return GitHubRelease{}, invalidSource("github_release_by_tag", "GitHub release tag is invalid")
	}
	return client.resolveRelease(ctx, owner, repository, tag, false)
}

type githubAPIRepository struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type githubAPIRelease struct {
	ID              int64  `json:"id"`
	TagName         string `json:"tag_name"`
	TargetCommitish string `json:"target_commitish"`
	Assets          []struct {
		ID                 int64  `json:"id"`
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

type githubAPICommit struct {
	SHA string `json:"sha"`
}

func (client *GitHubRESTReleaseClient) resolveRelease(ctx context.Context, owner, repository, tag string, latest bool) (GitHubRelease, error) {
	owner, repository, err := canonicalGitHubAPIRepository(owner, repository)
	if err != nil {
		return GitHubRelease{}, err
	}
	repositoryPath := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository)

	var repositoryResponse githubAPIRepository
	if err := client.getJSON(ctx, repositoryPath, &repositoryResponse); err != nil {
		return GitHubRelease{}, err
	}
	if repositoryResponse.ID <= 0 || !strings.EqualFold(repositoryResponse.Owner.Login, owner) || !strings.EqualFold(repositoryResponse.Name, repository) {
		return GitHubRelease{}, githubAPIError("github_repository", fmt.Errorf("GitHub repository identity is invalid"))
	}

	releasePath := repositoryPath + "/releases/latest"
	if !latest {
		releasePath = repositoryPath + "/releases/tags/" + url.PathEscape(tag)
	}
	var releaseResponse githubAPIRelease
	if err := client.getJSON(ctx, releasePath, &releaseResponse); err != nil {
		return GitHubRelease{}, err
	}
	if releaseResponse.ID <= 0 || releaseResponse.TagName == "" || len(releaseResponse.TagName) > 255 ||
		strings.TrimSpace(releaseResponse.TagName) != releaseResponse.TagName || containsControl(releaseResponse.TagName) ||
		(!latest && releaseResponse.TagName != tag) || releaseResponse.TargetCommitish == "" ||
		len(releaseResponse.TargetCommitish) > 255 || strings.TrimSpace(releaseResponse.TargetCommitish) != releaseResponse.TargetCommitish ||
		containsControl(releaseResponse.TargetCommitish) || len(releaseResponse.Assets) > githubAPIMaxAssets {
		return GitHubRelease{}, githubAPIError("github_release", fmt.Errorf("GitHub release identity is invalid"))
	}

	commitPath := repositoryPath + "/commits/" + url.PathEscape(releaseResponse.TargetCommitish)
	var commitResponse githubAPICommit
	if err := client.getJSON(ctx, commitPath, &commitResponse); err != nil {
		return GitHubRelease{}, err
	}
	if !isGitCommitSHA(commitResponse.SHA) || (isGitCommitSHA(releaseResponse.TargetCommitish) && commitResponse.SHA != releaseResponse.TargetCommitish) {
		return GitHubRelease{}, githubAPIError("github_commit", fmt.Errorf("GitHub commit identity is invalid"))
	}

	assets := make([]GitHubReleaseAsset, 0, len(releaseResponse.Assets))
	for _, asset := range releaseResponse.Assets {
		if asset.ID <= 0 || asset.Name == "" || len(asset.Name) > 255 || strings.TrimSpace(asset.Name) != asset.Name ||
			containsControl(asset.Name) || strings.ContainsAny(asset.Name, `/\`) || asset.BrowserDownloadURL == "" ||
			len(asset.BrowserDownloadURL) > maxSourceURLBytes || asset.Size < 0 {
			return GitHubRelease{}, githubAPIError("github_release", fmt.Errorf("GitHub release asset identity is invalid"))
		}
		download, parseErr := url.Parse(asset.BrowserDownloadURL)
		if parseErr != nil || download.Scheme != "https" || download.Hostname() == "" || download.User != nil || download.Fragment != "" {
			return GitHubRelease{}, githubAPIError("github_release", fmt.Errorf("GitHub release asset URL is invalid"))
		}
		assets = append(assets, GitHubReleaseAsset{
			AssetID: asset.ID, Name: asset.Name, DownloadURL: asset.BrowserDownloadURL, Size: asset.Size,
		})
	}
	return GitHubRelease{
		RepositoryID: repositoryResponse.ID, ReleaseID: releaseResponse.ID, Tag: releaseResponse.TagName,
		ResolvedCommitSHA: commitResponse.SHA, Assets: assets,
	}, nil
}

func canonicalGitHubAPIRepository(owner, repository string) (string, string, error) {
	if !githubOwnerPattern.MatchString(owner) || !githubRepositoryPattern.MatchString(repository) ||
		repository == "." || repository == ".." || strings.HasSuffix(strings.ToLower(repository), ".git") {
		return "", "", invalidSource("github_repository", "GitHub owner or repository is invalid")
	}
	return strings.ToLower(owner), strings.ToLower(repository), nil
}

func (client *GitHubRESTReleaseClient) getJSON(ctx context.Context, escapedPath string, destination any) error {
	if client == nil || client.http == nil || client.http.Transport == nil || !strings.HasPrefix(escapedPath, "/repos/") {
		return invalidSource("github_api", "GitHub REST client is not initialized")
	}
	requestURL, err := url.Parse(githubAPIOrigin + escapedPath)
	if err != nil || requestURL.Scheme != "https" || requestURL.Host != "api.github.com" || requestURL.User != nil || requestURL.RawQuery != "" || requestURL.Fragment != "" {
		return invalidSource("github_api", "GitHub API request path is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return githubAPIError("github_api", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", client.userAgent)
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	if client.token != "" {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return githubAPIError("github_api", err)
	}
	if response.Body == nil {
		return githubAPIError("github_api", fmt.Errorf("GitHub API response body is missing"))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return githubAPIError("github_api", fmt.Errorf("GitHub API returned HTTP status %d", response.StatusCode))
	}
	if encoding := strings.TrimSpace(response.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return githubAPIError("github_api", fmt.Errorf("GitHub API response encoding is unsupported"))
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "application/vnd.github+json") {
		return githubAPIError("github_api", fmt.Errorf("GitHub API response content type is invalid"))
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, githubAPIMaxResponseBytes+1))
	if err != nil {
		return githubAPIError("github_api", err)
	}
	if len(raw) == 0 || len(raw) > githubAPIMaxResponseBytes {
		return githubAPIError("github_api", fmt.Errorf("GitHub API response size is invalid"))
	}
	if err := validateGitHubAPIJSON(raw); err != nil {
		return githubAPIError("github_api", fmt.Errorf("GitHub API response JSON is invalid"))
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return githubAPIError("github_api", fmt.Errorf("GitHub API response projection is invalid"))
	}
	return nil
}

func validateGitHubAPIJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("root must be an object")
	}
	if err := validateGitHubAPIJSONObject(decoder, 1); err != nil {
		return err
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("mismatched root JSON delimiter")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validateGitHubAPIJSONObject(decoder *json.Decoder, depth int) error {
	if depth > githubAPIMaxJSONDepth {
		return errors.New("object nesting exceeds limit")
	}
	seen := make(map[string]struct{})
	items := 0
	for decoder.More() {
		items++
		if items > githubAPIMaxJSONItems {
			return errors.New("object field count exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("object field name is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("duplicate object field")
		}
		seen[name] = struct{}{}
		if err := validateGitHubAPIJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateGitHubAPIJSONArray(decoder *json.Decoder, depth int) error {
	if depth > githubAPIMaxJSONDepth {
		return errors.New("array nesting exceeds limit")
	}
	items := 0
	for decoder.More() {
		items++
		if items > githubAPIMaxJSONItems {
			return errors.New("array item count exceeds limit")
		}
		if err := validateGitHubAPIJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateGitHubAPIJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		if err := validateGitHubAPIJSONObject(decoder, depth); err != nil {
			return err
		}
	case '[':
		if err := validateGitHubAPIJSONArray(decoder, depth); err != nil {
			return err
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if (delimiter == '{' && closing != json.Delim('}')) || (delimiter == '[' && closing != json.Delim(']')) {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

func githubAPIError(operation string, cause error) error {
	return externalError(ErrorGitHubRelease, operation, githubAPIOrigin, cause)
}
