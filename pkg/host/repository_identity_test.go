package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/externalsource"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type identityGitHubResolver struct {
	externalPackageTestGitHubResolver
	resolved externalsource.ResolvedGitHubAsset
}

func (r identityGitHubResolver) ResolvePackage(context.Context, externalsource.GitHubRepositorySource) (externalsource.ResolvedGitHubAsset, error) {
	return r.resolved, nil
}

func TestRepositoryIdentityAdmissionAndLocalProvenance(t *testing.T) {
	for _, kind := range []string{"github_repository", "package_url", "package_upload"} {
		for _, repositoryID := range []int64{42, 43} {
			t.Run(fmt.Sprintf("%s/%d", kind, repositoryID), func(t *testing.T) {
				h, _, _ := newTestHostWithOptions(t, testHostOptions{})
				var document map[string]any
				if err := json.Unmarshal([]byte(hostReleaseManifestJSON()), &document); err != nil {
					t.Fatal(err)
				}
				document["publisher"].(map[string]any)["publisher_id"] = "github.repo.42"
				document["plugin"].(map[string]any)["plugin_id"] = "github.repo.42.example"
				raw, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				stage := &externalPackageTestStage{pkg: readTestPackage(t, buildHostReleasePackageFromManifest(t, string(raw)))}
				configureExternalPackageTestModule(h, stage)
				h.adapters.ExternalPackageGitHubResolver = identityGitHubResolver{resolved: externalsource.ResolvedGitHubAsset{
					PluginID: stage.pkg.Manifest.PluginID(), Version: stage.pkg.Manifest.Plugin.Version, RepositoryID: repositoryID,
					RepositoryURL: "https://github.com/example/plugins", ReleaseID: 7, AssetID: 8, AssetName: "plugin.redevplugin",
					Tag: "example-v1.0.0", ResolvedCommitSHA: strings.Repeat("a", 40), Fetch: externalsource.FetchResult{Artifact: stage.uploaded},
				}}
				var inspection ExternalPackageInspection
				if kind == "package_upload" {
					inspection, err = h.InspectUploadedExternalPackage(hostTestContext(), InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
				} else {
					inspection, err = h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Source: ExternalPackageSource{Kind: kind, URL: "https://github.com/example/plugins"}})
				}
				if kind == "github_repository" && repositoryID != 42 {
					if !errors.Is(err, ErrExternalPackageConfirmation) || stage.removedCount() != 1 {
						t.Fatalf("impostor admission: %v; cleanup: %d", err, stage.removedCount())
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if string(inspection.SourceProvenance.Kind) != kind {
					t.Fatalf("source promoted by declaration: %+v", inspection.SourceProvenance)
				}
				installed, err := h.installInspectedPackage(hostTestContext(), installInspectedPackageRequest{InspectionID: inspection.InspectionID, ExpectedPackageSHA256: inspection.InspectedHashes.PackageSHA256})
				if err != nil {
					t.Fatal(err)
				}
				if installed.Plugin.EnableState != registry.EnableEnabled || string(installed.Plugin.PackageSourceProvenance.Kind) != kind {
					t.Fatalf("installed provenance: %+v", installed.Plugin)
				}
				if kind == "github_repository" {
					before := stage.removedCount()
					resolver := h.adapters.ExternalPackageGitHubResolver.(identityGitHubResolver)
					resolver.resolved.RepositoryID = 43
					h.adapters.ExternalPackageGitHubResolver = resolver
					_, err = h.InspectExternalPackage(hostTestContext(), InspectExternalPackageRequest{
						Intent: ExternalPackageIntent{Action: "update", PluginInstanceID: installed.Plugin.PluginInstanceID, ExpectedManagementRevision: installed.Plugin.ManagementRevision, AllowSourceChange: true},
						Source: ExternalPackageSource{Kind: kind, URL: resolver.resolved.RepositoryURL},
					})
					if !errors.Is(err, ErrExternalPackageConfirmation) || stage.removedCount() != before+1 {
						t.Fatalf("explicit source change bypassed repository identity: %v", err)
					}
				}
			})
		}
	}
}
