// Package pluginidentity defines source-derived plugin identities. A declaration
// is not source evidence: callers must obtain the repository ID independently.
package pluginidentity

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const MaxRepositoryID int64 = 9007199254740991

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Identity struct {
	PublisherID string `json:"publisher_id"`
	PluginID    string `json:"plugin_id"`
}

func GitHub(repositoryID int64, slug string) (Identity, error) {
	if repositoryID <= 0 || repositoryID > MaxRepositoryID {
		return Identity{}, errors.New("repository ID must be a positive safe integer")
	}
	if len(slug) > 80 || !slugPattern.MatchString(slug) {
		return Identity{}, errors.New("plugin slug must contain 1 to 80 lowercase letters, digits or single separating hyphens")
	}
	publisher := "github.repo." + strconv.FormatInt(repositoryID, 10)
	return Identity{PublisherID: publisher, PluginID: publisher + "." + slug}, nil
}

func ValidateGitHub(repositoryID int64, publisherID, pluginID string) error {
	prefix, err := GitHub(repositoryID, "plugin")
	if err != nil {
		return err
	}
	slug, ok := strings.CutPrefix(pluginID, prefix.PublisherID+".")
	if !ok {
		return errors.New("plugin ID does not belong to the observed GitHub repository")
	}
	expected, err := GitHub(repositoryID, slug)
	if err != nil {
		return err
	}
	if publisherID != expected.PublisherID || pluginID != expected.PluginID {
		return errors.New("publisher and plugin identity do not match the observed GitHub repository")
	}
	return nil
}

// ValidateDeclaration checks only shape and internal consistency. It never
// authenticates a repository or upgrades a local/upload source into GitHub.
func ValidateDeclaration(publisherID, pluginID string) error {
	if !strings.HasPrefix(publisherID, "github.repo.") && !strings.HasPrefix(pluginID, "github.repo.") {
		return nil
	}
	suffix, ok := strings.CutPrefix(publisherID, "github.repo.")
	if !ok {
		return errors.New("GitHub plugin identity requires its repository-derived publisher")
	}
	id, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil || strconv.FormatInt(id, 10) != suffix {
		return fmt.Errorf("invalid repository-derived publisher ID %q", publisherID)
	}
	return ValidateGitHub(id, publisherID, pluginID)
}
