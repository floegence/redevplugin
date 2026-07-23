package externalsource

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const githubHost = "github.com"

var (
	githubOwnerPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

// GitHubRepositorySource selects either the latest release or one exact tag.
// RepositoryURL must be exactly https://github.com/{owner}/{repository}.
type GitHubRepositorySource struct {
	RepositoryURL string
	Tag           string
	QuotaKey      string
}

// GitHubReleaseClient owns GitHub API authentication and returns stable GitHub
// identities. The resolver never clones, checks out, builds, or executes source.
type GitHubReleaseClient interface {
	LatestRelease(ctx context.Context, owner, repository string) (GitHubRelease, error)
	ReleaseByTag(ctx context.Context, owner, repository, tag string) (GitHubRelease, error)
}

type GitHubRelease struct {
	RepositoryID int64
	ReleaseID    int64
	Tag          string
	// ResolvedCommitSHA is the immutable 40-character commit selected for the
	// release. Clients must resolve branch-like target_commitish values before
	// returning a release.
	ResolvedCommitSHA string
	Assets            []GitHubReleaseAsset
}

type GitHubReleaseAsset struct {
	AssetID     int64
	Name        string
	DownloadURL string
	Size        int64
}

// ResolvedGitHubAsset binds downloaded bytes to immutable GitHub release and
// asset identities. URLs in this result are safe for logs and persistence.
type ResolvedGitHubAsset struct {
	RepositoryURL     string
	RepositoryID      int64
	ReleaseID         int64
	Tag               string
	ResolvedCommitSHA string
	AssetID           int64
	AssetName         string
	DeclaredSize      int64
	Fetch             FetchResult
}

type GitHubReleaseResolver struct {
	client  GitHubReleaseClient
	fetcher *Fetcher
}

func NewGitHubReleaseResolver(client GitHubReleaseClient, fetcher *Fetcher) (*GitHubReleaseResolver, error) {
	if client == nil || fetcher == nil {
		return nil, invalidSource("new_github_resolver", "GitHub release client and fetcher are required")
	}
	return &GitHubReleaseResolver{client: client, fetcher: fetcher}, nil
}

// ResolvePackage selects the unique .redevplugin asset and downloads it
// through the same public-HTTPS, redirect, DNS, and staging policy as a direct
// URL. Signed download query parameters are accepted but never exposed.
func (resolver *GitHubReleaseResolver) ResolvePackage(ctx context.Context, source GitHubRepositorySource) (ResolvedGitHubAsset, error) {
	if resolver == nil || resolver.client == nil || resolver.fetcher == nil {
		return ResolvedGitHubAsset{}, invalidSource("resolve_github", "GitHub resolver is not initialized")
	}
	owner, repository, repositoryURL, err := parseGitHubRepositoryURL(source.RepositoryURL)
	if err != nil {
		return ResolvedGitHubAsset{}, err
	}
	tag := strings.TrimSpace(source.Tag)
	if tag != source.Tag || containsControl(tag) || len(tag) > 255 {
		return ResolvedGitHubAsset{}, invalidSource("resolve_github", "GitHub release tag is invalid")
	}

	var release GitHubRelease
	if tag == "" {
		release, err = resolver.client.LatestRelease(ctx, owner, repository)
	} else {
		release, err = resolver.client.ReleaseByTag(ctx, owner, repository, tag)
	}
	if err != nil {
		return ResolvedGitHubAsset{}, externalError(ErrorGitHubRelease, "resolve_github", repositoryURL, err)
	}
	if release.RepositoryID <= 0 || release.ReleaseID <= 0 || release.Tag == "" || strings.TrimSpace(release.Tag) != release.Tag || containsControl(release.Tag) || len(release.Tag) > 255 || (tag != "" && release.Tag != tag) || !isGitCommitSHA(release.ResolvedCommitSHA) {
		return ResolvedGitHubAsset{}, externalError(ErrorGitHubRelease, "resolve_github", repositoryURL, fmt.Errorf("release identity is invalid"))
	}

	asset, err := uniquePluginAsset(release.Assets, repositoryURL)
	if err != nil {
		return ResolvedGitHubAsset{}, err
	}
	if asset.Size > MaxArtifactBytes {
		return ResolvedGitHubAsset{}, externalError(ErrorArtifactTooLarge, "resolve_github", repositoryURL, fmt.Errorf("asset size exceeds limit"))
	}
	fetched, err := resolver.fetcher.fetchPackage(ctx, asset.DownloadURL, source.QuotaKey, true)
	if err != nil {
		return ResolvedGitHubAsset{}, err
	}
	if asset.Size > 0 && fetched.Artifact.Size != asset.Size {
		_ = resolver.fetcher.stage.Remove(fetched.Artifact)
		return ResolvedGitHubAsset{}, externalError(ErrorStageIntegrity, "resolve_github", repositoryURL, fmt.Errorf("downloaded asset size does not match release metadata"))
	}
	return ResolvedGitHubAsset{
		RepositoryURL:     repositoryURL,
		RepositoryID:      release.RepositoryID,
		ReleaseID:         release.ReleaseID,
		Tag:               release.Tag,
		ResolvedCommitSHA: release.ResolvedCommitSHA,
		AssetID:           asset.AssetID,
		AssetName:         asset.Name,
		DeclaredSize:      asset.Size,
		Fetch:             fetched,
	}, nil
}

func isGitCommitSHA(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func parseGitHubRepositoryURL(raw string) (owner, repository, display string, err error) {
	parsed, parseErr := url.Parse(raw)
	if parseErr != nil || raw == "" || strings.TrimSpace(raw) != raw || len(raw) > maxSourceURLBytes || containsControl(raw) {
		return "", "", "", invalidSource("parse_github_repository", "GitHub repository URL is invalid")
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), githubHost) || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", "", "", invalidSource("parse_github_repository", "GitHub repository URL must use the canonical public GitHub origin")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 2 || !githubOwnerPattern.MatchString(parts[0]) || !githubRepositoryPattern.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." || strings.HasSuffix(strings.ToLower(parts[1]), ".git") {
		return "", "", "", invalidSource("parse_github_repository", "GitHub repository URL must identify one owner and repository")
	}
	owner = strings.ToLower(parts[0])
	repository = strings.ToLower(parts[1])
	display = "https://" + githubHost + "/" + owner + "/" + repository
	return owner, repository, display, nil
}

func uniquePluginAsset(assets []GitHubReleaseAsset, displayURL string) (GitHubReleaseAsset, error) {
	matches := make([]GitHubReleaseAsset, 0, 1)
	for _, asset := range assets {
		if strings.TrimSpace(asset.Name) == asset.Name && strings.HasSuffix(strings.ToLower(asset.Name), ".redevplugin") {
			matches = append(matches, asset)
		}
	}
	if len(matches) == 0 {
		return GitHubReleaseAsset{}, externalError(ErrorGitHubAssetMissing, "resolve_github", displayURL, fmt.Errorf("release has no plugin package asset"))
	}
	if len(matches) != 1 {
		return GitHubReleaseAsset{}, externalError(ErrorGitHubAssetAmbiguous, "resolve_github", displayURL, fmt.Errorf("release has multiple plugin package assets"))
	}
	asset := matches[0]
	if asset.AssetID <= 0 || asset.Name == "" || len(asset.Name) > 255 || containsControl(asset.Name) || strings.ContainsAny(asset.Name, `/\`) || asset.DownloadURL == "" || asset.Size < 0 {
		return GitHubReleaseAsset{}, externalError(ErrorGitHubRelease, "resolve_github", displayURL, fmt.Errorf("release asset identity is invalid"))
	}
	return asset, nil
}
