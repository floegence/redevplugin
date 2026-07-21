package registry

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
)

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
				EnableState:       EnableDisabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.test", Version: "1.0.0"}},
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
				EnableState:       EnableEnabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.test", Version: "1.0.0"}},
				Metadata:          map[string]string{"trust.key_id": "publisher-key"},
			}
			stored, err := store.PutPlugin(registryTestContext(), record, PutOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			stored.Version = "2.0.0"
			stored.ActiveFingerprint = "sha256:v2"
			stored.PackageHash = "sha256:v2"
			stored.VersionHistory = []PluginVersion{{Version: "1.0.0", PackageHash: "sha256:v1"}}
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
				ReleaseTrustBinding:   &ReleaseTrustBinding{SourceID: "source.original"},
				LocalImportProvenance: &LocalImportProvenance{ImportID: "import_original", Distribution: "local_import"},
				CapabilityContracts: []capabilitycontract.Pin{{
					PublisherID:              "example.publisher",
					ContractID:               "example.documents.v1",
					ContractVersion:          "1.0.0",
					ArtifactRef:              "capabilities/documents/schema.json",
					ArtifactSHA256:           strings.Repeat("1", 64),
					ManifestRef:              "capabilities/documents/manifest.json",
					ManifestSHA256:           strings.Repeat("2", 64),
					SignatureRef:             "capabilities/documents/manifest.sig",
					SignatureSHA256:          strings.Repeat("3", 64),
					SignatureKeyID:           "documents-key",
					SignaturePolicyEpoch:     "1",
					SignatureRevocationEpoch: "1",
					CompatibilityRef:         "capabilities/documents/compatibility.json",
					CompatibilitySHA256:      strings.Repeat("4", 64),
					GeneratedClientRef:       "capabilities/documents/client.ts",
					GeneratedClientSHA256:    strings.Repeat("5", 64),
					NoticesRef:               "capabilities/documents/notices.json",
					NoticesSHA256:            strings.Repeat("6", 64),
				}},
				EnableState: EnableDisabled,
				Manifest: manifest.Manifest{
					Plugin: manifest.Plugin{PluginID: "com.example.clone", Version: "1.0.0"},
					Methods: []manifest.MethodSpec{{
						Method:        "documents.get",
						RequestSchema: map[string]any{"type": "object", "properties": map[string]any{"document_id": map[string]any{"type": "string"}}},
					}},
				},
				VersionHistory: []PluginVersion{{
					Version:             "0.9.0",
					ReleaseTrustBinding: &ReleaseTrustBinding{SourceID: "history.original"},
					Metadata:            map[string]string{"history": "original"},
				}},
				Metadata: map[string]string{"record": "original"},
			}
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
				got.Manifest.Methods[0].RequestSchema["properties"].(map[string]any)["document_id"].(map[string]any)["type"] != "string" ||
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
				EnableState:       EnableDisabled,
				Manifest:          manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.delete", Version: "1.0.0"}},
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

func TestSQLiteStorePersistsRecordsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	now := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(registryTestContext(), path)
	if err != nil {
		t.Fatal(err)
	}
	record := PluginRecord{
		PluginInstanceID:  "plugini_persist",
		PublisherID:       "example",
		PluginID:          "com.example.persist",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:persist",
		PackageHash:       "sha256:pkg",
		ManifestHash:      "sha256:manifest",
		EntriesHash:       "sha256:entries",
		TrustState:        TrustVerified,
		TrustAssessment: TrustAssessment{
			TrustState:  TrustVerified,
			ReasonCodes: []string{"sqlite_round_trip"},
			VerifiedHashes: TrustHashSet{
				PackageSHA256:  "sha256:pkg",
				ManifestSHA256: "sha256:manifest",
				EntriesSHA256:  "sha256:entries",
			},
			VerifiedSignature:    &VerifiedSignature{Algorithm: "ed25519", KeyID: "official"},
			TrustAssessmentEpoch: "trust_epoch_1",
			PolicyEpoch:          "1",
			RevocationEpoch:      "1",
			Metadata:             map[string]string{"trust.key_id": "official"},
		},
		LocalImportProvenance: &LocalImportProvenance{
			ImportID:       "local_import",
			Distribution:   "local_import",
			PolicyEpoch:    "local_import",
			UnsignedPolicy: "dev_only",
			AssessedAt:     "2026-06-29T00:00:00Z",
		},
		EnableState: EnableEnabled,
		Manifest:    manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.persist", Version: "1.0.0"}},
		RuntimeRequirement: &RuntimeRequirement{
			MinVersion:       "0.5.0",
			SupportedTargets: []runtimetarget.Target{runtimetarget.DarwinARM64, runtimetarget.LinuxAMD64},
		},
		VersionHistory: []PluginVersion{{
			Version: "0.9.0",
			RuntimeRequirement: &RuntimeRequirement{
				MinVersion:       "0.4.3",
				SupportedTargets: []runtimetarget.Target{runtimetarget.LinuxAMD64},
			},
		}},
		Metadata: map[string]string{"source": "sqlite-test"},
	}
	stored, err := store.PutPlugin(registryTestContext(), record, PutOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(registryTestContext(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})
	got, err := reopened.GetPlugin(registryTestContext(), stored.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PluginID != record.PluginID ||
		got.PackageHash != "sha256:pkg" ||
		got.Manifest.Plugin.PluginID != record.PluginID ||
		got.Metadata["source"] != "sqlite-test" ||
		got.TrustAssessment.TrustState != TrustVerified ||
		got.TrustAssessment.ReasonCodes[0] != "sqlite_round_trip" ||
		got.TrustAssessment.VerifiedSignature == nil ||
		got.TrustAssessment.VerifiedSignature.KeyID != "official" ||
		got.TrustAssessment.PolicyEpoch != "1" ||
		got.TrustAssessment.RevocationEpoch != "1" ||
		got.TrustAssessment.Metadata["trust.key_id"] != "official" ||
		got.LocalImportProvenance == nil ||
		got.LocalImportProvenance.UnsignedPolicy != "dev_only" ||
		got.RuntimeRequirement == nil ||
		got.RuntimeRequirement.MinVersion != "0.5.0" ||
		len(got.RuntimeRequirement.SupportedTargets) != 2 ||
		len(got.VersionHistory) != 1 ||
		got.VersionHistory[0].RuntimeRequirement == nil ||
		got.VersionHistory[0].RuntimeRequirement.MinVersion != "0.4.3" ||
		!got.InstalledAt.Equal(now) {
		t.Fatalf("persisted record mismatch: %#v", got)
	}
	listed, err := reopened.ListPlugins(registryTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].TrustAssessment.VerifiedSignature == nil || listed[0].TrustAssessment.VerifiedSignature.KeyID != "official" {
		t.Fatalf("ListPlugins() trust assessment mismatch: %#v", listed)
	}
	authorization, err := reopened.ListAuthorization(registryTestContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(authorization) != 1 || authorization[0].Plugin.RuntimeRequirement == nil || authorization[0].Plugin.RuntimeRequirement.MinVersion != "0.5.0" {
		t.Fatalf("ListAuthorization() runtime requirement mismatch: %#v", authorization)
	}
}

func TestSQLiteStoreMigratesRuntimeRequirementColumn(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	legacy, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	legacyRecord := PluginRecord{
		PluginInstanceID:  "plugini_runtime_migration",
		PublisherID:       "example",
		PluginID:          "com.example.runtime-migration",
		Version:           "1.0.0",
		ActiveFingerprint: "sha256:runtime-migration",
		TrustState:        TrustVerified,
		EnableState:       EnableDisabled,
		Manifest: manifest.Manifest{
			Plugin:  manifest.Plugin{PluginID: "com.example.runtime-migration", Version: "1.0.0", MinRuntimeVersion: "0.5.0"},
			Workers: []manifest.WorkerSpec{{WorkerID: "current-worker"}},
		},
		VersionHistory: []PluginVersion{{
			Version: "0.4.3",
			Manifest: manifest.Manifest{
				Plugin:  manifest.Plugin{PluginID: "com.example.runtime-migration", Version: "0.4.3", MinRuntimeVersion: "0.4.3"},
				Workers: []manifest.WorkerSpec{{WorkerID: "historic-worker"}},
			},
		}},
	}
	if _, err := legacy.PutPlugin(ctx, legacyRecord, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.db.ExecContext(ctx, `ALTER TABLE plugin_records DROP COLUMN runtime_requirement_json`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	got, err := migrated.GetPlugin(ctx, legacyRecord.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RuntimeRequirement == nil || got.RuntimeRequirement.MinVersion != "0.5.0" || len(got.RuntimeRequirement.SupportedTargets) != 0 {
		t.Fatalf("migrated current runtime requirement = %#v", got.RuntimeRequirement)
	}
	if len(got.VersionHistory) != 1 || got.VersionHistory[0].RuntimeRequirement == nil || got.VersionHistory[0].RuntimeRequirement.MinVersion != "0.4.3" || len(got.VersionHistory[0].RuntimeRequirement.SupportedTargets) != 0 {
		t.Fatalf("migrated historic runtime requirement = %#v", got.VersionHistory)
	}
}

func TestSQLiteStoreRejectsUnknownPersistedRuntimeTargets(t *testing.T) {
	ctx := registryTestContext()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record, err := store.PutPlugin(ctx, PluginRecord{
		PluginInstanceID: "plugini_unknown_target",
		PublisherID:      "example",
		PluginID:         "com.example.unknown-target",
		Version:          "1.0.0",
		TrustState:       TrustVerified,
		EnableState:      EnableDisabled,
		Manifest:         manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.unknown-target", Version: "1.0.0"}},
		RuntimeRequirement: &RuntimeRequirement{
			MinVersion:       "0.5.0",
			SupportedTargets: []runtimetarget.Target{runtimetarget.LinuxAMD64},
		},
	}, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		column string
		value  string
	}{
		{column: "runtime_requirement_json", value: `{"min_version":"0.5.0","supported_targets":["windows/amd64"]}`},
		{column: "version_history_json", value: `[{"version":"0.9.0","runtime_requirement":{"min_version":"0.5.0","supported_targets":["linux/x86_64"]}}]`},
	} {
		t.Run(test.column, func(t *testing.T) {
			if _, err := store.db.ExecContext(ctx, `UPDATE plugin_records SET runtime_requirement_json = ?, version_history_json = ? WHERE plugin_instance_id = ?`, `{"min_version":"0.5.0","supported_targets":["linux/amd64"]}`, `[]`, record.PluginInstanceID); err != nil {
				t.Fatal(err)
			}
			query := "UPDATE plugin_records SET " + test.column + " = ? WHERE plugin_instance_id = ?"
			if _, err := store.db.ExecContext(ctx, query, test.value, record.PluginInstanceID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetPlugin(ctx, record.PluginInstanceID); !errors.Is(err, runtimetarget.ErrUnsupported) {
				t.Fatalf("GetPlugin() error = %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestRunnableTrustState(t *testing.T) {
	for _, state := range []TrustState{TrustVerified, TrustUnsignedLocal} {
		if !RunnableTrustState(state) {
			t.Fatalf("%s should be runnable", state)
		}
	}
	for _, state := range []TrustState{TrustUntrusted, TrustNeedsReview, TrustUnavailable, TrustBlockedSecurity} {
		if RunnableTrustState(state) {
			t.Fatalf("%s should not be runnable", state)
		}
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
		{
			name: "sqlite",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := NewSQLiteStore(registryTestContext(), filepath.Join(t.TempDir(), "registry.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = store.Close()
				})
				return store
			},
		},
	}
}
