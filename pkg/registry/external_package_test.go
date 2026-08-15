package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v2/pkg/manifest"
)

func TestPrepareExternalPackageInstallBindsOwnerAndRevision(t *testing.T) {
	now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
	req := externalPackageInstallRequest("owner_env_a", now)
	installed, err := PrepareExternalPackageInstall("owner_env_a", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if installed.ManagementRevision != 1 || installed.OwnerEnvHash != "owner_env_a" || !RunnablePluginRecord(installed) {
		t.Fatalf("prepared record = %#v", installed)
	}
	if _, err := PrepareExternalPackageInstall("owner_env_b", req, nil); !errors.Is(err, ErrInvalidExternalPackageInstall) {
		t.Fatalf("cross-owner prepare error = %v", err)
	}
	if _, err := PrepareExternalPackageInstall("owner_env_a", req, &installed); !errors.Is(err, ErrManagementRevisionConflict) {
		t.Fatalf("duplicate prepare error = %v", err)
	}
}

func TestExternalPackageInstallRejectsInvalidOrRevokedSignature(t *testing.T) {
	for _, status := range []SignatureAssessmentStatus{SignatureInvalid, SignatureRevoked} {
		t.Run(string(status), func(t *testing.T) {
			req := externalPackageInstallRequest("owner_env_hash_test", time.Now().UTC())
			req.Record.SignatureAssessment.Status = status
			req.Record.ExecutionApproval.Status = ExecutionApprovalPolicyBlocked
			if _, err := PrepareExternalPackageInstall("owner_env_hash_test", req, nil); !errors.Is(err, ErrInvalidExternalPackageInstall) {
				t.Fatalf("PrepareExternalPackageInstall() error = %v", err)
			}
		})
	}
}

func TestExternalPackageInstallPreservesDisabledZeroGrantManualOnly(t *testing.T) {
	req := externalPackageInstallRequest("owner_env_hash_test", time.Now().UTC())
	installed, err := PrepareExternalPackageInstall("owner_env_hash_test", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if installed.EnableState != EnableDisabled || installed.UpdateEligibility != UpdateManualOnly {
		t.Fatalf("installed security state = %#v", installed)
	}
	if installed.PolicyRevision != 1 {
		t.Fatalf("prepared policy revision = %d, want 1", installed.PolicyRevision)
	}
}

func TestSQLiteRegistryHasNoExternalInspectionOrReceiptTable(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, table := range []string{"external_package_commit_receipts", "external_package_inspections"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("durable external package transient table %q exists", table)
		}
	}
}

func TestSQLiteRegistryRejectsLegacyExternalReceiptTableWithoutChangingSource(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE external_package_commit_receipts (legacy TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = 4`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)
	if reopened, err := NewSQLiteStore(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() accepted an ambiguous legacy receipt table")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if afterHash := sha256.Sum256(after); afterHash != beforeHash {
		t.Fatal("failed open changed the legacy registry bytes")
	}
}

func TestSQLiteRegistryPreservesPopulatedHistoricalV5ExternalReceiptTable(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	createHistoricalV5ExternalPackageReceiptTable(t, store.db)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO external_package_commit_receipts VALUES(
  'env','inspection','commit','install','confirmation','request',0,
  'fingerprint','package','plugin','committed','committed','{}','',1,2
)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = 5`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewSQLiteStore(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() discarded a historical external package receipt")
	}
	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, receipts int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM external_package_commit_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if version != 5 || receipts != 1 {
		t.Fatalf("failed migration changed historical state: version=%d receipts=%d", version, receipts)
	}
}

func TestSQLiteRegistryRejectsHistoricalV5ReceiptConstraintDrift(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	createHistoricalV5ExternalPackageReceiptTableWithoutCommitUniqueness(t, store.db)
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = 5`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewSQLiteStore(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() accepted historical receipt constraint drift")
	}
}

func createHistoricalV5ExternalPackageReceiptTableWithoutCommitUniqueness(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
CREATE TABLE external_package_commit_receipts (
    owner_env_hash TEXT NOT NULL, inspection_id TEXT NOT NULL, commit_id TEXT NOT NULL,
    intent TEXT NOT NULL, confirmation_digest TEXT NOT NULL, request_sha256 TEXT NOT NULL,
    expected_management_revision INTEGER NOT NULL, intended_fingerprint TEXT NOT NULL,
    intended_package_sha256 TEXT NOT NULL, plugin_instance_id TEXT NOT NULL, status TEXT NOT NULL,
    mutation_outcome TEXT NOT NULL, record_snapshot_json TEXT NOT NULL DEFAULT 'null',
    failure_code TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    PRIMARY KEY(owner_env_hash, inspection_id)
)`); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteRegistryRejectsFutureSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `PRAGMA user_version = 999`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if store, err := NewSQLiteStore(registryTestContext(), path); err == nil {
		_ = store.Close()
		t.Fatal("NewSQLiteStore() accepted future schema version")
	}
}

func externalPackageInstallRequest(ownerEnvHash string, now time.Time) InstallExternalPackageRequest {
	packageHash := "sha256:external-package"
	return InstallExternalPackageRequest{
		Intent: ExternalPackageInstall, Now: now,
		Record: PluginRecord{
			PluginInstanceID: "plugini_external", PublisherID: "example", PluginID: "com.example.external", Version: "1.0.0",
			ActiveFingerprint: "sha256:external-fingerprint", PackageHash: packageHash, ManifestHash: "sha256:manifest", EntriesHash: "sha256:entries",
			TrustState: TrustNeedsReview,
			SignatureAssessment: SignatureAssessment{Status: SignatureAbsent,
				AssessedHashes: TrustHashSet{PackageSHA256: packageHash, ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries"},
				PackageSHA256:  packageHash, ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries"},
			PackageSourceProvenance: PackageSourceProvenance{Kind: PackageSourceGitHubRepository, RepositoryURL: "https://github.com/example/plugin",
				GitHubRepositoryID: "R_123", GitHubReleaseID: "REL_123", GitHubAssetID: "ASSET_123", PackageSHA256: packageHash},
			ExecutionApproval: ExecutionApproval{Status: ExecutionApprovalUserApproved, OwnerEnvHash: ownerEnvHash, PackageSHA256: packageHash},
			UpdateEligibility: UpdateManualOnly, EnableState: EnableDisabled,
			SecurityCapabilitySummary: SecurityCapabilitySummary{SchemaVersion: "security-capability-summary-v1", CanonicalJSON: `{"network":false}`, SHA256: "sha256:capability-summary"},
			Manifest:                  manifest.Manifest{SchemaVersion: manifest.SchemaVersionV8, Plugin: manifest.Plugin{PluginID: "com.example.external", Version: "1.0.0"}},
		},
	}
}
