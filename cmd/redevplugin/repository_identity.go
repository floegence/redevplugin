package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
)

// Publication identity is resolved from GitHub, never from numeric author input.
func resolvePublicationIdentity(ctx context.Context, root, repository, slug string) (pluginidentity.Identity, error) {
	if err := pluginidentity.ValidateSlug(slug); err != nil {
		return pluginidentity.Identity{}, err
	}
	if repository == "" {
		raw, err := exec.CommandContext(ctx, "git", "-C", root, "remote", "get-url", "origin").Output()
		if err != nil {
			return pluginidentity.Identity{}, errors.New("publishing requires a Git origin or --repository https://github.com/owner/repo")
		}
		repository = strings.TrimSpace(string(raw))
	}
	repository = strings.TrimSuffix(repository, ".git")
	if strings.HasPrefix(repository, "git@github.com:") {
		repository = "https://github.com/" + strings.TrimPrefix(repository, "git@github.com:")
	}
	if strings.HasPrefix(repository, "ssh://git@github.com/") {
		repository = "https://github.com/" + strings.TrimPrefix(repository, "ssh://git@github.com/")
	}
	client, err := externalsource.NewGitHubRESTReleaseClient(externalsource.GitHubRESTReleaseClientOptions{Token: os.Getenv("GITHUB_TOKEN")})
	if err != nil {
		return pluginidentity.Identity{}, err
	}
	defer client.CloseIdleConnections()
	id, err := client.RepositoryID(ctx, repository)
	if err != nil {
		return pluginidentity.Identity{}, err
	}
	return pluginidentity.GitHub(id, slug)
}
