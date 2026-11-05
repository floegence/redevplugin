package host

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

type SetAutomaticUpdatesRequest struct {
	PluginInstanceID           string `json:"plugin_instance_id"`
	ExpectedManagementRevision uint64 `json:"expected_management_revision"`
	Enabled                    bool   `json:"enabled"`
}
type InspectPluginUpdateRequest struct {
	PluginInstanceID           string `json:"plugin_instance_id"`
	ExpectedManagementRevision uint64 `json:"expected_management_revision"`
}

// SetAutomaticUpdates stores the user's preference on the existing installation.
// It never grants permissions or changes package approval.
func (h *Host) SetAutomaticUpdates(ctx context.Context, req SetAutomaticUpdatesRequest) (result registry.PluginRecord, retErr error) {
	authorization, err := h.authorizeManagement(ctx, ManagementActionSetAutomaticUpdates, scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment))
	if err != nil {
		return result, err
	}
	ctx, reservation, err := h.reserveAuthorizedAction(ctx, authorization)
	if err != nil {
		return result, err
	}
	defer reservation()
	release, err := h.ensureOpen()
	if err != nil {
		return result, err
	}
	defer release()
	unlock, err := h.lifecycleLocks.acquireWrite(ctx, req.PluginInstanceID)
	if err != nil {
		return result, err
	}
	defer unlock()
	current, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return result, err
	}
	if err = requireManagementRevision(current, req.ExpectedManagementRevision); err != nil {
		return result, err
	}
	if req.Enabled && !retrievableUpdateSource(current.PackageSourceProvenance) {
		return result, fmt.Errorf("%w: this installation has no update source", ErrExternalPackageRequestInvalid)
	}
	if current.AutomaticUpdates == req.Enabled {
		return current, nil
	}
	audit, err := h.beginSecurityMutation(ctx, AuditEvent{Type: "plugin.automatic_updates.changed", PluginID: current.PluginID, PluginInstanceID: current.PluginInstanceID})
	if err != nil {
		return result, err
	}
	defer func() { retErr = audit.complete(context.WithoutCancel(ctx), retErr) }()
	current.AutomaticUpdates = req.Enabled
	current.UpdateEligibility = registry.UpdateManualOnly
	if req.Enabled {
		current.UpdateEligibility = registry.UpdateAutomaticEligible
	}
	stored, err := h.putPluginRecord(ctx, current, time.Now().UTC())
	if err != nil {
		return result, err
	}
	if err = h.revokePluginRuntimeCapabilities(ctx, stored, time.Now().UTC()); err != nil {
		return stored, mutation.Committed(err)
	}
	if err = h.refreshEnabledRuntimeState(ctx, stored); err != nil {
		return stored, mutation.Committed(err)
	}
	return stored, nil
}

// InspectPluginUpdate resolves only the installation's original source. Hosts
// call this API for both manual checks and user-enabled background checks.
func (h *Host) InspectPluginUpdate(ctx context.Context, req InspectPluginUpdateRequest) (ExternalPackageInspection, error) {
	release, err := h.ensureOpen()
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	defer release()
	if err = h.requireFeature(FeatureExternalPackage); err != nil {
		return ExternalPackageInspection{}, err
	}
	if _, err := h.authorizeManagement(ctx, ManagementActionInspectExternalPackage, scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return ExternalPackageInspection{}, err
	}
	current, err := h.getPluginRecord(ctx, req.PluginInstanceID)
	if err != nil {
		return ExternalPackageInspection{}, err
	}
	if err = requireManagementRevision(current, req.ExpectedManagementRevision); err != nil {
		return ExternalPackageInspection{}, err
	}
	source := ExternalPackageSource{Kind: string(current.PackageSourceProvenance.Kind)}
	switch current.PackageSourceProvenance.Kind {
	case registry.PackageSourceGitHubRepository:
		source.URL = current.PackageSourceProvenance.RepositoryURL
		source.PluginID = current.PluginID
		source.RepositoryID = current.PackageSourceProvenance.GitHubRepositoryID
	case registry.PackageSourcePackageURL:
		source.URL = current.PackageSourceProvenance.SourceURL
	default:
		return ExternalPackageInspection{}, fmt.Errorf("%w: select a package source explicitly", ErrExternalPackageRequestInvalid)
	}
	return h.InspectExternalPackage(ctx, InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "update", PluginInstanceID: current.PluginInstanceID, ExpectedManagementRevision: current.ManagementRevision}, Source: source, ExpectedPublisherID: current.PublisherID, ExpectedPluginID: current.PluginID})
}

func retrievableUpdateSource(source registry.PackageSourceProvenance) bool {
	return source.Kind == registry.PackageSourceGitHubRepository && source.GitHubRepositoryID != "" && source.RepositoryURL != "" || source.Kind == registry.PackageSourcePackageURL && source.SourceURL != ""
}
func validateAutomaticUpdate(current, next registry.PluginRecord) error {
	if !current.AutomaticUpdates || !retrievableUpdateSource(current.PackageSourceProvenance) {
		return fmt.Errorf("%w: automatic updates are not enabled", ErrExternalPackageRequestInvalid)
	}
	if err := validatePackageUpdate(current, next, false); err != nil {
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
	if after.Compare(before) <= 0 {
		return fmt.Errorf("%w: no newer version", ErrExternalPackageRequestInvalid)
	}
	var a, b ExternalPackageSecuritySummary
	if json.Unmarshal([]byte(current.SecurityCapabilitySummary.CanonicalJSON), &a) != nil || json.Unmarshal([]byte(next.SecurityCapabilitySummary.CanonicalJSON), &b) != nil {
		return fmt.Errorf("%w: review package capabilities", ErrUpdateReviewRequired)
	}
	normalize := func(s *ExternalPackageSecuritySummary) {
		s.SummarySHA256 = ""
		for i := range s.Surfaces {
			s.Surfaces[i].Label = ""
			s.Surfaces[i].Icon = ""
			s.Surfaces[i].DefaultSize = nil
		}
	}
	normalize(&a)
	normalize(&b)
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("%w: capabilities changed; review the update", ErrUpdateReviewRequired)
	}
	return nil
}

type ListRepositoryPluginsRequest struct {
	URL  string `json:"url"`
	Host string `json:"host,omitempty"`
}

func (h *Host) ListRepositoryPlugins(ctx context.Context, req ListRepositoryPluginsRequest) ([]repositoryindex.Plugin, error) {
	if _, err := h.authorizeManagement(ctx, ManagementActionListRepositoryPlugins, authorizationCollectionTarget(ResourcePlugin)); err != nil {
		return nil, err
	}
	release, err := h.ensureOpen()
	if err != nil {
		return nil, err
	}
	defer release()
	if err = h.requireFeature(FeatureExternalPackage); err != nil {
		return nil, err
	}
	return h.adapters.ExternalPackageGitHubResolver.ListPlugins(ctx, req.URL, req.Host)
}
