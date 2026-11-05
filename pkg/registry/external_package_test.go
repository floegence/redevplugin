package registry

import (
	"errors"
	"testing"
	"time"
)

func TestPrepareExternalPackageInstallBindsOwnerAndRevision(t *testing.T) {
	now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
	req := externalPackageInstallRequest("owner_env_a", now)
	installed, err := PrepareExternalPackageInstall("owner_env_a", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if installed.ManagementRevision != 1 || installed.RevokeEpoch != 1 || installed.OwnerEnvHash != "owner_env_a" || !RunnablePluginRecord(installed) {
		t.Fatalf("prepared record = %#v", installed)
	}
	if _, err := PrepareExternalPackageInstall("owner_env_b", req, nil); !errors.Is(err, ErrInvalidExternalPackageInstall) {
		t.Fatalf("cross-owner prepare error = %v", err)
	}
	if _, err := PrepareExternalPackageInstall("owner_env_a", req, &installed); !errors.Is(err, ErrManagementRevisionConflict) {
		t.Fatalf("duplicate prepare error = %v", err)
	}
}

func TestPrepareExternalPackageReinstallInheritsDeletedRevokeFloor(t *testing.T) {
	now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
	req := externalPackageInstallRequest("owner_env_a", now)
	deletedAt := now.Add(-time.Minute)
	tombstone := req.Record
	tombstone.OwnerEnvHash = "owner_env_a"
	tombstone.ManagementRevision = 7
	tombstone.RevokeEpoch = 5
	tombstone.DeletedAt = &deletedAt

	reinstalled, err := PrepareExternalPackageInstall("owner_env_a", req, &tombstone)
	if err != nil {
		t.Fatal(err)
	}
	if reinstalled.ManagementRevision != 1 || reinstalled.RevokeEpoch != tombstone.RevokeEpoch || reinstalled.DeletedAt != nil {
		t.Fatalf("reinstalled record = %#v", reinstalled)
	}
}

func TestExternalPackageInstallEnablesByDefaultWithoutGrant(t *testing.T) {
	req := externalPackageInstallRequest("owner_env_hash_test", time.Now().UTC())
	installed, err := PrepareExternalPackageInstall("owner_env_hash_test", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if installed.EnableState != EnableEnabled || installed.UpdateEligibility != UpdateManualOnly {
		t.Fatalf("installed security state = %#v", installed)
	}
	if installed.PolicyRevision != 1 {
		t.Fatalf("prepared policy revision = %d, want 1", installed.PolicyRevision)
	}
}

func TestCurrentPluginRecordRequiresExplicitPackageSourceProvenance(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	record := externalPackageInstallRequest("owner_env_hash_test", now).Record
	record.PackageSourceProvenance = PackageSourceProvenance{}
	if _, err := PreparePluginPut("owner_env_hash_test", record, nil, now); err == nil {
		t.Fatal("PreparePluginPut() inferred source provenance from legacy trust state")
	}
	if RunnablePluginRecord(record) {
		t.Fatal("RunnablePluginRecord() accepted a record without explicit source provenance")
	}
}

func TestExternalSourceDoesNotInferExecutionApproval(t *testing.T) {
	now := time.Date(2026, 8, 17, 1, 2, 3, 0, time.UTC)
	record := externalPackageInstallRequest("owner_env_hash_test", now).Record
	record.ExecutionApproval = ExecutionApproval{}

	stored, err := PreparePluginPut("owner_env_hash_test", record, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ExecutionApproval.Status != ExecutionApprovalPending || RunnablePluginRecord(stored) {
		t.Fatalf("external execution approval = %#v", stored.ExecutionApproval)
	}
}

func TestVersionHistorySecurityNormalizationDoesNotInferLifecycleApproval(t *testing.T) {
	record := normalizePluginSecurityFacts(PluginRecord{
		OwnerEnvHash: "owner_env_hash_test",
		EnableState:  EnableEnabled,
		VersionHistory: []PluginVersion{{
			Version:      "0.9.0",
			PackageHash:  "sha256:history-package",
			ManifestHash: "sha256:history-manifest",
			EntriesHash:  "sha256:history-entries",
		}},
	})

	history := record.VersionHistory[0]
	if history.ExecutionApproval.Status != ExecutionApprovalPending {
		t.Fatalf("history execution approval = %q, want pending", history.ExecutionApproval.Status)
	}
	if history.ExecutionApproval.OwnerEnvHash != record.OwnerEnvHash || history.ExecutionApproval.PackageSHA256 != history.PackageHash {
		t.Fatalf("history execution approval binding = %#v", history.ExecutionApproval)
	}
}

func externalPackageInstallRequest(ownerEnvHash string, now time.Time) InstallExternalPackageRequest {
	packageHash := "sha256:external-package"
	return InstallExternalPackageRequest{
		Intent: ExternalPackageInstall,
		Now:    now,
		Record: PluginRecord{
			PluginInstanceID:  "plugini_external",
			PublisherID:       "example",
			PluginID:          "com.example.external",
			Version:           "1.0.0",
			ActiveFingerprint: "sha256:external-fingerprint",
			PackageHash:       packageHash,
			ManifestHash:      "sha256:manifest",
			EntriesHash:       "sha256:entries",

			PackageSourceProvenance: PackageSourceProvenance{
				Kind: PackageSourceGitHubRepository, RepositoryURL: "https://github.com/example/plugin",
				GitHubRepositoryID: "R_123", GitHubReleaseID: "REL_123", GitHubAssetID: "ASSET_123", PackageSHA256: packageHash,
			},
			ExecutionApproval: ExecutionApproval{
				Status: ExecutionApprovalUserApproved, OwnerEnvHash: ownerEnvHash, PackageSHA256: packageHash,
			},
			UpdateEligibility: UpdateManualOnly,
			EnableState:       EnableEnabled,
			SecurityCapabilitySummary: SecurityCapabilitySummary{
				SchemaVersion: "security-capability-summary-v1", CanonicalJSON: `{"network":false}`, SHA256: "sha256:capability-summary",
			},
			Manifest: currentTestManifest("com.example.external", "1.0.0"),
		},
	}
}
