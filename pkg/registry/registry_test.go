package registry

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/plugindata"
)

func currentTestManifest(pluginID, version string) manifest.Manifest {
	return manifest.Manifest{
		SchemaVersion: manifest.SchemaVersionV9,
		Publisher:     manifest.Publisher{PublisherID: "example"},
		Plugin:        manifest.Plugin{PluginID: pluginID, DisplayName: "Test Plugin", Version: version},
		API:           manifest.PublicAPIRequirement{Major: manifest.PluginAPIMajor},
		Permissions:   []manifest.PermissionID{},
		Presentation: manifest.PresentationSpec{
			DefaultLocale: "en-US",
			Summary:       "Test plugin",
			Description:   []string{"Test plugin"},
			Highlights:    []string{},
			Keywords:      []string{"test"},
			Localizations: []manifest.PresentationLocalizationSpec{},
		},
		Surfaces: []manifest.SurfaceSpec{{
			SurfaceID: "main",
			Kind:      manifest.SurfaceView,
			Label:     "Test",
			Entry:     "ui/index.html",
		}},
	}
}

func TestStoreRevisionsAndList(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
			record := PluginRecord{
				PluginInstanceID:  "plugini_test",
				PublisherID:       "example",
				PluginID:          "com.example.test",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:test",
				TrustState:        TrustVerified,
				PackageSourceProvenance: PackageSourceProvenance{
					Kind: PackageSourceLocalGenerated,
				},
				EnableState: EnableDisabledByUser,
				Manifest:    currentTestManifest("com.example.test", "1.0.0"),
			}
			stored, err := store.PutPlugin(registryTestContext(), record, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if stored.PolicyRevision != 1 || stored.ManagementRevision != 1 || stored.RevokeEpoch != 0 {
				t.Fatalf("initial revisions = %#v", stored)
			}

			enabled, err := store.SetEnableState(registryTestContext(), stored.PluginInstanceID, EnableEnabled, "", now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if enabled.ManagementRevision != 2 || enabled.RevokeEpoch != 1 || enabled.EnabledAt == nil {
				t.Fatalf("enable revisions = %#v", enabled)
			}

			granted, err := store.GrantPermission(registryTestContext(), permissions.GrantRequest{
				PluginInstanceID: stored.PluginInstanceID,
				PermissionID:     "documents.read",
				Now:              now.Add(2 * time.Second),
			}, AuthorizationRevisionsFromRecord(enabled))
			if err != nil {
				t.Fatal(err)
			}
			if granted.Plugin.PolicyRevision != 2 || granted.Plugin.ManagementRevision != 2 || granted.Plugin.RevokeEpoch != 1 {
				t.Fatalf("grant policy revisions = %#v", granted)
			}

			revoked, err := store.RevokePermission(registryTestContext(), permissions.RevokeRequest{
				PluginInstanceID: stored.PluginInstanceID,
				PermissionID:     "documents.read",
				Now:              now.Add(3 * time.Second),
			}, AuthorizationRevisionsFromRecord(granted.Plugin))
			if err != nil {
				t.Fatal(err)
			}
			if revoked.Plugin.PolicyRevision != 3 || revoked.Plugin.ManagementRevision != 2 || revoked.Plugin.RevokeEpoch != 2 {
				t.Fatalf("revoke policy revisions = %#v", revoked)
			}

			_, err = store.CommitUninstall(registryTestContext(), plugindata.CommitUninstallRequest{
				PluginInstanceID:           revoked.Plugin.PluginInstanceID,
				DeleteData:                 true,
				ExpectedManagementRevision: revoked.Plugin.ManagementRevision,
				Now:                        now.Add(4 * time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
			list, err := store.ListPlugins(registryTestContext())
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 0 {
				t.Fatalf("ListPlugins() returned deleted record: %#v", list)
			}
		})
	}
}

func TestStorePreservesVersionHistoryOnOverwrite(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
			record := PluginRecord{
				PluginInstanceID:  "plugini_test",
				PublisherID:       "example",
				PluginID:          "com.example.test",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:v1",
				PackageHash:       "sha256:v1",
				TrustState:        TrustVerified,
				PackageSourceProvenance: PackageSourceProvenance{
					Kind: PackageSourceLocalGenerated,
				},
				EnableState: EnableEnabled,
				Manifest:    currentTestManifest("com.example.test", "1.0.0"),
				Metadata:    map[string]string{"trust.key_id": "publisher-key"},
			}
			stored, err := store.PutPlugin(registryTestContext(), record, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			stored.Version = "2.0.0"
			stored.ActiveFingerprint = "sha256:v2"
			stored.PackageHash = "sha256:v2"
			stored.SignatureAssessment = SignatureAssessment{}
			stored.PackageSourceProvenance.PackageSHA256 = "sha256:v2"
			stored.ExecutionApproval = ExecutionApproval{}
			stored.UpdateEligibility = ""
			stored.VersionHistory = []PluginVersion{{
				Version: "1.0.0", PackageHash: "sha256:v1",
				PackageSourceProvenance: PackageSourceProvenance{Kind: PackageSourceLocalGenerated},
				Manifest:                currentTestManifest("com.example.test", "1.0.0"),
			}}
			updated, err := store.PutPlugin(registryTestContext(), stored, PutOptions{Now: now.Add(time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			if updated.ManagementRevision != 2 ||
				updated.RevokeEpoch != 1 ||
				len(updated.VersionHistory) != 1 ||
				updated.VersionHistory[0].Version != "1.0.0" ||
				updated.Metadata["trust.key_id"] != "publisher-key" {
				t.Fatalf("updated record mismatch: %#v", updated)
			}
		})
	}
}

func TestStoreDeepClonesNestedPluginRecords(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			record := PluginRecord{
				PluginInstanceID:  "plugini_clone",
				PublisherID:       "example.publisher",
				PluginID:          "com.example.clone",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:clone",
				TrustState:        TrustVerified,
				TrustAssessment: TrustAssessment{
					TrustState:  TrustVerified,
					ReasonCodes: []string{"verified"},
					Metadata:    map[string]string{"key": "original"},
				},
				PackageHash:  "sha256:package-current",
				ManifestHash: "sha256:manifest-current",
				EntriesHash:  "sha256:entries-current",
				PackageSourceProvenance: PackageSourceProvenance{
					Kind: PackageSourceLocalGenerated,
				},
				ReleaseTrustBinding:   testReleaseTrustBinding("source.original", "1.0.0"),
				LocalImportProvenance: &LocalImportProvenance{ImportID: "import_original", Distribution: "local_import"},
				CapabilityContracts: []capabilitycontract.Pin{{
					PublisherID:     "example.publisher",
					ContractID:      "example.documents.v1",
					ContractVersion: "1.0.0",
					ArtifactSHA256:  strings.Repeat("1", 64),
				}},
				EnableState: EnableEnabled,
				Manifest: manifest.Manifest{SchemaVersion: manifest.SchemaVersionV9,
					Publisher: manifest.Publisher{PublisherID: "example"},
					Plugin:    manifest.Plugin{PluginID: "com.example.clone", DisplayName: "Clone", Version: "1.0.0"},
					API:       manifest.PublicAPIRequirement{Major: manifest.PluginAPIMajor},
					Presentation: manifest.PresentationSpec{DefaultLocale: "en-US", Summary: "Clone", Description: []string{"Clone"},
						Keywords: []string{"clone"}},
					Surfaces: []manifest.SurfaceSpec{{SurfaceID: "main", Kind: manifest.SurfaceView, Label: "Clone", Entry: "ui/index.html"}},
					Methods: []manifest.MethodSpec{{
						Method:        "documents.get",
						Effect:        manifest.MethodEffectRead,
						Execution:     manifest.MethodExecutionSync,
						RequestSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"document_id": map[string]any{"type": "string"}}},
						ResponseSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
							"document_id": map[string]any{"type": "string"},
						}},
						Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCoreAction, ActionID: "documents.get"},
					}},
				},
				VersionHistory: []PluginVersion{{
					Version:           "0.9.0",
					ActiveFingerprint: "sha256:history-fingerprint",
					PackageHash:       "sha256:package-history",
					ManifestHash:      "sha256:manifest-history",
					EntriesHash:       "sha256:entries-history",
					PackageSourceProvenance: PackageSourceProvenance{
						Kind: PackageSourceLocalGenerated,
					},
					ReleaseTrustBinding: testReleaseTrustBinding("history.original", "0.9.0"),
					Manifest:            currentTestManifest("com.example.clone", "0.9.0"),
					Metadata:            map[string]string{"history": "original"},
				}},
				Metadata: map[string]string{"record": "original"},
			}
			canonical, err := manifest.MarshalCanonical(record.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			historyCanonical, err := manifest.MarshalCanonical(record.VersionHistory[0].Manifest)
			if err != nil {
				t.Fatal(err)
			}
			record.CanonicalManifest = string(canonical)
			record.VersionHistory[0].CanonicalManifest = string(historyCanonical)
			stored, err := store.PutPlugin(registryTestContext(), record, PutOptions{})
			if err != nil {
				t.Fatal(err)
			}

			record.ReleaseTrustBinding.SourceID = "source.mutated-input"
			record.TrustAssessment.Metadata["key"] = "mutated-input"
			stored.ReleaseTrustBinding.SourceID = "source.mutated-return"
			stored.Manifest.Methods[0].RequestSchema["properties"].(map[string]any)["document_id"].(map[string]any)["type"] = "number"
			stored.VersionHistory[0].Metadata["history"] = "mutated-return"

			got, err := store.GetPlugin(registryTestContext(), record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.ReleaseTrustBinding.SourceID != "source.original" ||
				got.TrustAssessment.Metadata["key"] != "original" ||
				got.CanonicalManifest != string(canonical) ||
				got.Manifest.Methods[0].RequestSchema["properties"].(map[string]any)["document_id"].(map[string]any)["type"] != "string" ||
				got.VersionHistory[0].CanonicalManifest != string(historyCanonical) ||
				got.VersionHistory[0].Metadata["history"] != "original" {
				t.Fatalf("stored plugin record was mutated through an input or return boundary: %#v", got)
			}

			got.Metadata["record"] = "mutated-get"
			listed, err := store.ListPlugins(registryTestContext())
			if err != nil {
				t.Fatal(err)
			}
			listed[0].CapabilityContracts[0].ArtifactSHA256 = strings.Repeat("0", 64)
			again, err := store.GetPlugin(registryTestContext(), record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if again.Metadata["record"] != "original" || again.CapabilityContracts[0].ArtifactSHA256 != strings.Repeat("1", 64) {
				t.Fatalf("stored plugin record was mutated through get/list: %#v", again)
			}
		})
	}
}

func testReleaseTrustBinding(sourceID string, version string) *ReleaseTrustBinding {
	return &ReleaseTrustBinding{
		SourceID: sourceID, Channel: "stable", ReleaseMetadataRef: "plugins/example/release.json",
		ReleaseMetadataSHA256: strings.Repeat("1", 64), PublisherID: "example.publisher",
		PluginID: "com.example.clone", Version: version,
		RootEpoch: "1", PolicyEpoch: "1", RevocationEpoch: "1",
	}
}

func TestStoreAbortInstall(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			record := PluginRecord{
				PluginInstanceID:  "plugini_delete",
				PublisherID:       "example",
				PluginID:          "com.example.delete",
				Version:           "1.0.0",
				ActiveFingerprint: "sha256:delete",
				TrustState:        TrustVerified,
				PackageSourceProvenance: PackageSourceProvenance{
					Kind: PackageSourceLocalGenerated,
				},
				EnableState: EnableEnabled,
				Manifest:    currentTestManifest("com.example.delete", "1.0.0"),
			}
			if _, err := store.PutPlugin(registryTestContext(), record, PutOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := store.AbortInstall(registryTestContext(), record.PluginInstanceID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetPlugin(registryTestContext(), record.PluginInstanceID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetPlugin() after delete error = %v, want %v", err, ErrNotFound)
			}
			if err := store.AbortInstall(registryTestContext(), record.PluginInstanceID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("AbortInstall() after delete error = %v, want %v", err, ErrNotFound)
			}
		})
	}
}

type registryStoreCase struct {
	name string
	open func(t *testing.T) Store
}

func registryStoreCases() []registryStoreCase {
	return []registryStoreCase{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemoryStore()
			},
		},
	}
}
