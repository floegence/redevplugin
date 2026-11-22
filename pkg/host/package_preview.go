package host

import (
	"context"
	"strconv"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type PreviewPackageRequest struct {
	Source                     *ExternalPackageSource `json:"source,omitempty"`
	PluginInstanceID           string                 `json:"plugin_instance_id,omitempty"`
	ExpectedManagementRevision uint64                 `json:"expected_management_revision,omitempty"`
}

type PackagePreview struct {
	Kind         string `json:"kind"`
	PluginID     string `json:"plugin_id,omitempty"`
	Version      string `json:"version,omitempty"`
	Tag          string `json:"tag,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	ReleaseID    string `json:"release_id,omitempty"`
	AssetID      string `json:"asset_id,omitempty"`
	Size         int64  `json:"size,omitempty"`
}

func (h *Host) PreviewExternalPackage(ctx context.Context, req PreviewPackageRequest) (PackagePreview, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return PackagePreview{}, err
	}
	defer release()
	if err := h.requireFeature(FeatureExternalPackage); err != nil {
		return PackagePreview{}, err
	}
	switch {
	case req.Source == nil && (req.PluginInstanceID == "" || req.ExpectedManagementRevision == 0):
		return PackagePreview{}, ErrExternalPackageRequestInvalid
	case req.Source != nil && (req.PluginInstanceID != "" || req.ExpectedManagementRevision != 0):
		return PackagePreview{}, ErrExternalPackageRequestInvalid
	}
	target := scopedAuthorizationTargetOrCollection(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)
	if _, err := h.authorizeManagement(ctx, ManagementActionInspectExternalPackage, target); err != nil {
		return PackagePreview{}, err
	}
	var source ExternalPackageSource
	if req.Source == nil {
		record, err := h.getPluginRecord(ctx, req.PluginInstanceID)
		if err != nil {
			return PackagePreview{}, err
		}
		if err := requireManagementRevision(record, req.ExpectedManagementRevision); err != nil {
			return PackagePreview{}, err
		}
		source, err = installedUpdateSource(record)
		if err != nil {
			return PackagePreview{}, err
		}
	} else {
		source = *req.Source
	}
	switch source.Kind {
	case string(registry.PackageSourcePackageURL):
		if source.Tag != "" || source.Host != "" || source.PluginID != "" || source.RepositoryID != "" || source.ReleaseID != "" || source.AssetID != "" {
			return PackagePreview{}, ErrExternalPackageRequestInvalid
		}
		if _, err := externalsource.ParseDirectPackageURL(source.URL); err != nil {
			return PackagePreview{}, err
		}
		return PackagePreview{Kind: source.Kind}, nil
	case string(registry.PackageSourceGitHubRepository):
		resolver, ok := h.adapters.ExternalPackageGitHubResolver.(interface {
			PreviewPackage(context.Context, externalsource.GitHubRepositorySource) (externalsource.GitHubPackagePreview, error)
		})
		if !ok {
			return PackagePreview{}, ErrExternalPackageRequestInvalid
		}
		metadata, err := resolver.PreviewPackage(ctx, externalsource.GitHubRepositorySource{RepositoryURL: source.URL, Tag: source.Tag, Host: source.Host, PluginID: source.PluginID})
		if err != nil {
			return PackagePreview{}, err
		}
		result := PackagePreview{Kind: source.Kind, PluginID: metadata.PluginID, Version: metadata.Version, Tag: metadata.Tag, Size: metadata.DeclaredSize, RepositoryID: strconv.FormatInt(metadata.RepositoryID, 10), ReleaseID: strconv.FormatInt(metadata.ReleaseID, 10), AssetID: strconv.FormatInt(metadata.AssetID, 10)}
		if source.RepositoryID != "" && result.RepositoryID != source.RepositoryID || source.ReleaseID != "" && result.ReleaseID != source.ReleaseID || source.AssetID != "" && result.AssetID != source.AssetID {
			return PackagePreview{}, ErrExternalPackageConfirmation
		}
		return result, nil
	default:
		return PackagePreview{}, ErrExternalPackageRequestInvalid
	}
}
