package externalsource

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

// RepositoryIndex reads the fixed discovery entry at one resolved commit.
func (client *GitHubRESTReleaseClient) RepositoryIndex(ctx context.Context, owner, repository string) (repositoryindex.Index, error) {
	owner, repository, err := canonicalGitHubAPIRepository(owner, repository)
	if err != nil {
		return repositoryindex.Index{}, err
	}
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository)
	var repo struct {
		githubAPIRepository
		DefaultBranch string `json:"default_branch"`
	}
	if err = client.getJSON(ctx, base, &repo); err != nil {
		return repositoryindex.Index{}, err
	}
	if repo.ID <= 0 || repo.ID > pluginidentity.MaxRepositoryID || !strings.EqualFold(repo.Owner.Login, owner) || !strings.EqualFold(repo.Name, repository) || repo.DefaultBranch == "" || len(repo.DefaultBranch) > 255 {
		return repositoryindex.Index{}, invalidSource("github_index", "repository identity is invalid")
	}
	var commit githubAPICommit
	if err = client.getJSON(ctx, base+"/commits/"+url.PathEscape(repo.DefaultBranch), &commit); err != nil {
		return repositoryindex.Index{}, err
	}
	if !isGitCommitSHA(commit.SHA) {
		return repositoryindex.Index{}, invalidSource("github_index", "index commit is invalid")
	}
	var file struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int    `json:"size"`
		Path     string `json:"path"`
	}
	if err = client.getJSON(ctx, base+"/contents/"+repositoryindex.IndexPath+"?ref="+commit.SHA, &file); err != nil {
		return repositoryindex.Index{}, err
	}
	if file.Type != "file" || file.Encoding != "base64" || file.Path != repositoryindex.IndexPath || file.Size <= 0 || file.Size > repositoryindex.MaxBytes {
		return repositoryindex.Index{}, invalidSource("github_index", "repository index is not a bounded regular file")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil || len(raw) != file.Size {
		return repositoryindex.Index{}, invalidSource("github_index", "repository index content is invalid")
	}
	index, err := repositoryindex.Decode(raw)
	if err != nil {
		return repositoryindex.Index{}, err
	}
	identity, err := pluginidentity.GitHub(repo.ID, "plugin")
	if err != nil {
		return repositoryindex.Index{}, invalidSource("github_index", "repository identity is invalid")
	}
	for _, target := range index.Targets {
		for _, plugin := range target.Plugins {
			if err := pluginidentity.ValidateGitHub(repo.ID, identity.PublisherID, plugin.PluginID); err != nil {
				return repositoryindex.Index{}, invalidSource("github_index", "%v", err)
			}
		}
	}
	return index, nil
}

type GitHubReleaseTag struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// ReleaseTags is bounded and fails on truncation so an incomplete page set can
// never be reported as the newest plugin version.
func (client *GitHubRESTReleaseClient) ReleaseTags(ctx context.Context, owner, repository string) ([]GitHubReleaseTag, error) {
	owner, repository, err := canonicalGitHubAPIRepository(owner, repository)
	if err != nil {
		return nil, err
	}
	out := []GitHubReleaseTag{}
	seen := make(map[string]bool)
	for page := 1; page <= 10; page++ {
		var batch []GitHubReleaseTag
		path := fmt.Sprintf("/repos/%s/%s/releases?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repository), page)
		if err = client.getJSON(ctx, path, &batch); err != nil {
			return nil, err
		}
		if len(batch) > 100 {
			return nil, invalidSource("github_releases", "release page exceeds limit")
		}
		for _, release := range batch {
			if release.Tag == "" || len(release.Tag) > 255 || strings.TrimSpace(release.Tag) != release.Tag || containsControl(release.Tag) || seen[release.Tag] {
				return nil, invalidSource("github_releases", "release listing changed or contains an invalid tag")
			}
			seen[release.Tag] = true
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			return out, nil
		}
	}
	return nil, invalidSource("github_releases", "release listing exceeds limit")
}

func selectRepositoryPlugin(index repositoryindex.Index, host, pluginID string) (repositoryindex.Plugin, error) {
	if err := repositoryindex.Validate(index); err != nil {
		return repositoryindex.Plugin{}, err
	}
	found := map[string]repositoryindex.Plugin{}
	for _, target := range index.Targets {
		if host != "" && target.Host != host {
			continue
		}
		for _, p := range target.Plugins {
			if pluginID == "" || p.PluginID == pluginID {
				found[p.PluginID] = p
			}
		}
	}
	if len(found) != 1 {
		return repositoryindex.Plugin{}, invalidSource("github_index", "select one plugin from the repository index")
	}
	for _, p := range found {
		return p, nil
	}
	panic("unreachable")
}
func selectPluginTag(plugin repositoryindex.Plugin, tags []GitHubReleaseTag) (string, error) {
	var selected string
	var latest version.SemVer
	for _, r := range tags {
		if r.Draft || r.Prerelease {
			continue
		}
		v, err := repositoryindex.VersionFromTag(plugin.Release.TagTemplate, r.Tag)
		if err != nil {
			continue
		}
		parsed, err := version.ParseSemVer(v)
		if err != nil {
			continue
		}
		if selected == "" || parsed.Compare(latest) > 0 {
			selected = r.Tag
			latest = parsed
		}
	}
	if selected == "" {
		return "", externalError(ErrorGitHubRelease, "resolve_github", "", fmt.Errorf("no stable release matches the selected plugin"))
	}
	return selected, nil
}

// ListPlugins exposes the same validated index used by package resolution so a
// host can present a choice without maintaining its own GitHub/index parser.
func (resolver *GitHubReleaseResolver) ListPlugins(ctx context.Context, repositoryURL, host string) ([]repositoryindex.Plugin, error) {
	if resolver == nil || resolver.client == nil {
		return nil, invalidSource("github_index", "resolver is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	owner, repository, _, err := parseGitHubRepositoryURL(repositoryURL)
	if err != nil {
		return nil, err
	}
	index, err := resolver.client.RepositoryIndex(ctx, owner, repository)
	if err != nil {
		return nil, err
	}
	if err = repositoryindex.Validate(index); err != nil {
		return nil, err
	}
	out := []repositoryindex.Plugin{}
	seen := map[string]bool{}
	for _, target := range index.Targets {
		if host != "" && target.Host != host {
			continue
		}
		for _, plugin := range target.Plugins {
			if !seen[plugin.PluginID] {
				seen[plugin.PluginID] = true
				out = append(out, plugin)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out, nil
}
