package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
)

// The CLI resolves the repository itself. No publisher ID or numeric repository
// ID is accepted as an author-supplied authority input.
func runRepositoryIdentity(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: redevplugin repository identity <project-root> <slug> [--repository https://github.com/owner/repo]")
	}
	flags := flag.NewFlagSet("repository identity", flag.ContinueOnError)
	repository := flags.String("repository", "", "GitHub repository URL; defaults to the enclosing Git origin")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected repository identity arguments")
	}
	root, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if _, err = pluginidentity.GitHub(1, args[1]); err != nil {
		return err
	}
	source := *repository
	if source == "" {
		raw, e := exec.CommandContext(ctx, "git", "-C", root, "remote", "get-url", "origin").Output()
		if e != nil {
			return errors.New("set a Git origin or pass --repository https://github.com/owner/repo")
		}
		source = strings.TrimSpace(string(raw))
	}
	source = strings.TrimSuffix(source, ".git")
	if strings.HasPrefix(source, "git@github.com:") {
		source = "https://github.com/" + strings.TrimPrefix(source, "git@github.com:")
	}
	if strings.HasPrefix(source, "ssh://git@github.com/") {
		source = "https://github.com/" + strings.TrimPrefix(source, "ssh://git@github.com/")
	}
	client, err := externalsource.NewGitHubRESTReleaseClient(externalsource.GitHubRESTReleaseClientOptions{Token: os.Getenv("GITHUB_TOKEN")})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	repositoryID, err := client.RepositoryID(ctx, source)
	if err != nil {
		return err
	}
	identity, err := writeRepositoryIdentity(root, repositoryID, args[1])
	if err != nil {
		return err
	}
	return writeJSON(identity)
}

func writeRepositoryIdentity(root string, repositoryID int64, slug string) (pluginidentity.Identity, error) {
	identity, err := pluginidentity.GitHub(repositoryID, slug)
	if err != nil {
		return identity, err
	}
	path := filepath.Join(root, "manifest.json")
	info, err := os.Lstat(path)
	if err != nil {
		return identity, err
	}
	if !info.Mode().IsRegular() {
		return identity, errors.New("manifest must be a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return identity, err
	}
	// Validate the original before applying a narrow identity-only rewrite.
	if _, _, err = manifest.DecodeCanonical(bytes.NewReader(raw)); err != nil {
		return identity, err
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(raw, &doc); err != nil {
		return identity, err
	}
	for _, field := range []struct{ name, key, value string }{{"publisher", "publisher_id", identity.PublisherID}, {"plugin", "plugin_id", identity.PluginID}} {
		var object map[string]json.RawMessage
		if err = json.Unmarshal(doc[field.name], &object); err != nil {
			return identity, err
		}
		object[field.key], _ = json.Marshal(field.value)
		doc[field.name], err = json.Marshal(object)
		if err != nil {
			return identity, err
		}
	}
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return identity, err
	}
	updated = append(updated, '\n')
	if _, _, err = manifest.DecodeCanonical(bytes.NewReader(updated)); err != nil {
		return identity, err
	}
	if bytes.Equal(raw, updated) {
		return identity, nil
	}
	temporary, err := os.CreateTemp(root, ".manifest-identity-*.json")
	if err != nil {
		return identity, err
	}
	defer os.Remove(temporary.Name())
	if err = temporary.Chmod(info.Mode().Perm()); err == nil {
		_, err = temporary.Write(updated)
	}
	if err == nil {
		err = temporary.Sync()
	}
	err = errors.Join(err, temporary.Close())
	if err != nil {
		return identity, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return identity, err
	}
	now, err := os.ReadFile(path)
	if err != nil {
		return identity, err
	}
	if !os.SameFile(info, current) || !bytes.Equal(raw, now) {
		return identity, fmt.Errorf("manifest changed while resolving repository identity; retry")
	}
	if err = os.Rename(temporary.Name(), path); err != nil {
		return identity, err
	}
	return identity, nil
}
