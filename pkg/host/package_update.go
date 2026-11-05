package host

import (
	"errors"
	"fmt"

	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

var ErrUpdateReviewRequired = errors.New("plugin update requires review")

func validatePackageUpdate(current, next registry.PluginRecord, allowSourceChange bool) error {
	if err := validateSamePluginIdentity(current, next); err != nil {
		return err
	}
	before, err := version.ParseSemVer(current.Version)
	if err != nil {
		return err
	}
	after, err := version.ParseSemVer(next.Version)
	if err != nil {
		return err
	}
	if after.Compare(before) < 0 {
		return fmt.Errorf("%w: use explicit downgrade for an older version", ErrExternalPackageRequestInvalid)
	}
	if after.Compare(before) == 0 && current.PackageHash != next.PackageHash {
		return fmt.Errorf("%w: the same version has different package contents", ErrExternalPackageConfirmation)
	}
	for _, prior := range current.VersionHistory {
		if prior.Version == next.Version && prior.PackageHash != next.PackageHash {
			return fmt.Errorf("%w: retained version has different contents", ErrExternalPackageConfirmation)
		}
	}
	if !samePackageUpdateSource(current.PackageSourceProvenance, next.PackageSourceProvenance) && !allowSourceChange {
		return fmt.Errorf("%w: confirm the change of installation source", ErrUpdateReviewRequired)
	}
	return nil
}
func samePackageUpdateSource(a, b registry.PackageSourceProvenance) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case registry.PackageSourceGitHubRepository:
		return a.GitHubRepositoryID != "" && a.GitHubRepositoryID == b.GitHubRepositoryID
	case registry.PackageSourcePackageURL:
		return a.SourceURL != "" && a.SourceURL == b.SourceURL
	case registry.PackageSourcePackageUpload, registry.PackageSourceLocalPackage:
		return true
	default:
		return false
	}
}
