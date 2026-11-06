// Package pluginidentity defines source-derived plugin identities. A declaration
// is not source evidence: callers must obtain the repository ID independently.
package pluginidentity

import (
	"errors"
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
