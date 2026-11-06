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
	if err := ValidateSlug(slug); err != nil {
		return Identity{}, err
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

// ValidateSlug checks the only identity field maintained by a plugin author.
func ValidateSlug(slug string) error {
	if len(slug) > 80 || !slugPattern.MatchString(slug) {
		return errors.New("plugin slug must contain 1 to 80 lowercase letters, digits or single separating hyphens")
	}
	return nil
}

// Validate checks the exact generated GitHub identity shape. It is not source evidence.
func Validate(identity Identity) error {
	const prefix = "github.repo."
	if !strings.HasPrefix(identity.PublisherID, prefix) {
		return errors.New("unsupported publication identity")
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(identity.PublisherID, prefix), 10, 64)
	if err != nil {
		return err
	}
	return ValidateGitHub(id, identity.PublisherID, identity.PluginID)
}
