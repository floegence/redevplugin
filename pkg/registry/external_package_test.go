package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/mutation"
)

func TestExternalPackageCommitReplayAndOwnerIsolation(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			ctx := registryTestContextFor("owner_user_a", "owner_env_a")
			now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
			req := externalPackageInstallRequest("owner_env_a", now)
			committed, err := store.CommitExternalPackage(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if committed.Status != ExternalPackageCommitted || committed.MutationOutcome != mutation.OutcomeCommitted || committed.RecordSnapshot == nil {
				t.Fatalf("commit result = %#v", committed)
			}
			if !RunnablePluginRecord(*committed.RecordSnapshot) {
				t.Fatal("user-approved unsigned external package should be runnable")
			}

			if _, err := store.SetEnableState(ctx, req.Record.PluginInstanceID, EnableEnabled, "", now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			replayed, err := store.CommitExternalPackage(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if replayed.RecordSnapshot == nil || replayed.RecordSnapshot.ManagementRevision != 1 || replayed.RecordSnapshot.EnableState != EnableDisabled {
				t.Fatalf("replay did not preserve immutable commit snapshot: %#v", replayed.RecordSnapshot)
			}

			mismatch := req
			mismatch.Record.SecurityCapabilitySummary.CanonicalJSON = `{"changed":true}`
			if _, err := store.CommitExternalPackage(ctx, mismatch); !errors.Is(err, ErrExternalPackageCommitConflict) {
				t.Fatalf("payload mismatch error = %v", err)
			}
			otherOwner := registryTestContextFor("owner_user_b", "owner_env_b")
			if _, err := store.QueryExternalPackageCommit(otherOwner, QueryExternalPackageCommitRequest{InspectionID: req.InspectionID}); !errors.Is(err, ErrExternalPackageCommitNotFound) {
				t.Fatalf("cross-owner query error = %v", err)
			}
		})
	}
}

func TestExternalPackageCommitConcurrentReplay(t *testing.T) {
	for _, tc := range registryStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.open(t)
			req := externalPackageInstallRequest("owner_env_hash_test", time.Time{})
			const callers = 12
			var wg sync.WaitGroup
			errs := make(chan error, callers)
			for range callers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					result, err := store.CommitExternalPackage(registryTestContext(), req)
					if err == nil && (result.RecordSnapshot == nil || result.RecordSnapshot.ManagementRevision != 1) {
						err = errors.New("unexpected committed snapshot")
					}
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := store.GetPlugin(registryTestContext(), req.Record.PluginInstanceID)
			if err != nil {
				t.Fatal(err)
			}
			if got.ManagementRevision != 1 {
				t.Fatalf("management revision = %d, want 1", got.ManagementRevision)
			}
		})
	}
}

func TestExternalPackageCommitRejectsInvalidSecurityFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PluginRecord)
	}{
		{name: "unknown signature status", mutate: func(record *PluginRecord) { record.SignatureAssessment.Status = "future" }},
		{name: "unknown source kind", mutate: func(record *PluginRecord) { record.PackageSourceProvenance.Kind = "future" }},
		{name: "unknown approval status", mutate: func(record *PluginRecord) { record.ExecutionApproval.Status = "future" }},
		{name: "unknown update eligibility", mutate: func(record *PluginRecord) { record.UpdateEligibility = "future" }},
		{name: "mismatched signature package", mutate: func(record *PluginRecord) { record.SignatureAssessment.PackageSHA256 = "sha256:other" }},
		{name: "mismatched assessed manifest", mutate: func(record *PluginRecord) { record.SignatureAssessment.AssessedHashes.ManifestSHA256 = "sha256:other" }},
		{name: "mismatched signature entries", mutate: func(record *PluginRecord) { record.SignatureAssessment.EntriesSHA256 = "sha256:other" }},
		{name: "mismatched source package", mutate: func(record *PluginRecord) { record.PackageSourceProvenance.PackageSHA256 = "sha256:other" }},
		{name: "mismatched approval owner", mutate: func(record *PluginRecord) { record.ExecutionApproval.OwnerEnvHash = "other-owner" }},
		{name: "mismatched approval package", mutate: func(record *PluginRecord) { record.ExecutionApproval.PackageSHA256 = "sha256:other" }},
		{name: "invalid signature", mutate: func(record *PluginRecord) { record.SignatureAssessment.Status = SignatureInvalid }},
		{name: "revoked signature", mutate: func(record *PluginRecord) { record.SignatureAssessment.Status = SignatureRevoked }},
		{name: "unsigned automatic update", mutate: func(record *PluginRecord) { record.UpdateEligibility = UpdateAutomaticEligible }},
	}
	for _, storeCase := range registryStoreCases() {
		for _, test := range tests {
			t.Run(storeCase.name+"/"+test.name, func(t *testing.T) {
				store := storeCase.open(t)
				req := externalPackageInstallRequest("owner_env_hash_test", time.Time{})
				test.mutate(&req.Record)
				if RunnablePluginRecord(req.Record) && req.Record.SignatureAssessment.Status == "future" {
					t.Fatal("unknown signature status was runnable")
				}
				if _, err := store.CommitExternalPackage(registryTestContext(), req); !errors.Is(err, ErrInvalidExternalPackageCommit) && !errors.Is(err, ErrOwnerScopeMismatch) {
					t.Fatalf("CommitExternalPackage() error = %v", err)
				}
			})
		}
	}
}

func TestExternalPackageCommitRejectsMalformedConfirmationDigest(t *testing.T) {
	for _, storeCase := range registryStoreCases() {
		t.Run(storeCase.name, func(t *testing.T) {
			store := storeCase.open(t)
			req := externalPackageInstallRequest("owner_env_hash_test", time.Time{})
			req.ConfirmationDigest = "sha256:short"
			if _, err := store.CommitExternalPackage(registryTestContext(), req); !errors.Is(err, ErrInvalidExternalPackageCommit) {
				t.Fatalf("CommitExternalPackage() error = %v", err)
			}
		})
	}
}

func TestSQLiteExternalPackageCommitUnknownOutcomeIsQueryable(t *testing.T) {
	ctx := registryTestContext()
	store, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.commitTx = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("transport failed after commit")
	}
	req := externalPackageInstallRequest("owner_env_hash_test", time.Time{})
	if _, err := store.CommitExternalPackage(ctx, req); mutation.ForError(err) != mutation.OutcomeUnknown {
		t.Fatalf("commit error = %v, outcome = %q", err, mutation.ForError(err))
	}
	queried, err := store.QueryExternalPackageCommit(ctx, QueryExternalPackageCommitRequest{InspectionID: req.InspectionID, CommitID: req.CommitID})
	if err != nil {
		t.Fatal(err)
	}
	if queried.Status != ExternalPackageCommitted || queried.RecordSnapshot == nil || queried.MutationOutcome != mutation.OutcomeCommitted {
		t.Fatalf("queried result = %#v", queried)
	}
}

func TestSQLiteRegistryRejectsFutureSchemaVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = `+fmt.Sprint(registrySQLiteSchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(ctx, path); err == nil {
		t.Fatal("NewSQLiteStore() accepted a future schema version")
	}
}

func TestSQLiteRegistryRejectsFutureSchemaBeforeChangingJournalMode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	dsn, err := registrySQLiteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode = DELETE`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = `+fmt.Sprint(registrySQLiteSchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteStore(ctx, path); err == nil {
		t.Fatal("NewSQLiteStore() accepted a future schema version")
	}
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("failed future-schema open changed journal mode to %q", journalMode)
	}
}

func TestSQLiteRegistryRejectsCurrentSchemaShapeDriftWithoutRepair(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(context.Context, *sql.DB) error
		check  func(context.Context, *sql.DB) (bool, error)
	}{
		{
			name: "missing required index",
			mutate: func(ctx context.Context, db *sql.DB) error {
				_, err := db.ExecContext(ctx, `DROP INDEX idx_plugin_records_plugin_id`)
				return err
			},
			check: func(ctx context.Context, db *sql.DB) (bool, error) {
				var count int
				err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_plugin_records_plugin_id'`).Scan(&count)
				return count == 0, err
			},
		},
		{
			name: "missing ordinary column",
			mutate: func(ctx context.Context, db *sql.DB) error {
				_, err := db.ExecContext(ctx, `ALTER TABLE plugin_records DROP COLUMN metadata_json`)
				return err
			},
			check: func(ctx context.Context, db *sql.DB) (bool, error) {
				var count int
				err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('plugin_records') WHERE name = 'metadata_json'`).Scan(&count)
				return count == 0, err
			},
		},
		{
			name: "missing receipt commit uniqueness",
			mutate: func(ctx context.Context, db *sql.DB) error {
				_, err := db.ExecContext(ctx, `
ALTER TABLE external_package_commit_receipts RENAME TO external_package_commit_receipts_old;
CREATE TABLE external_package_commit_receipts (
    owner_env_hash TEXT NOT NULL, inspection_id TEXT NOT NULL, commit_id TEXT NOT NULL, intent TEXT NOT NULL,
    confirmation_digest TEXT NOT NULL, request_sha256 TEXT NOT NULL, expected_management_revision INTEGER NOT NULL,
    intended_fingerprint TEXT NOT NULL, intended_package_sha256 TEXT NOT NULL, plugin_instance_id TEXT NOT NULL,
    status TEXT NOT NULL, mutation_outcome TEXT NOT NULL, record_snapshot_json TEXT NOT NULL DEFAULT 'null',
    failure_code TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    PRIMARY KEY(owner_env_hash, inspection_id)
);
DROP TABLE external_package_commit_receipts_old;`)
				return err
			},
			check: func(ctx context.Context, db *sql.DB) (bool, error) {
				rows, err := db.QueryContext(ctx, `PRAGMA index_list(external_package_commit_receipts)`)
				if err != nil {
					return false, err
				}
				defer rows.Close()
				for rows.Next() {
					var sequence, unique, partial int
					var name, origin string
					if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
						return false, err
					}
					if origin == "u" {
						return false, nil
					}
				}
				return true, rows.Err()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "registry.sqlite")
			store, err := NewSQLiteStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(ctx, store.db); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := NewSQLiteStore(ctx, path); err == nil {
				_ = reopened.Close()
				t.Fatal("NewSQLiteStore() repaired current schema drift")
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
			unchanged, err := test.check(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			if !unchanged {
				t.Fatal("failed current-schema open modified the drifted schema")
			}
		})
	}
}

func TestSQLiteRegistryRejectsMalformedCurrentSecurityFactsWithoutRepair(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.PutPlugin(ctx, PluginRecord{
		PluginInstanceID: "plugini_malformed_facts", PublisherID: "example", PluginID: "com.example.malformed",
		Version: "1.0.0", PackageHash: "sha256:package", TrustState: TrustVerified, EnableState: EnableDisabled,
		Manifest: manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.malformed", Version: "1.0.0"}},
	}, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE plugin_records SET signature_assessment_json = '{"state":"future"}' WHERE plugin_instance_id = ?`, record.PluginInstanceID); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewSQLiteStore(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() accepted malformed current security facts")
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
	var signatureJSON string
	if err := db.QueryRowContext(ctx, `SELECT signature_assessment_json FROM plugin_records WHERE plugin_instance_id = ?`, record.PluginInstanceID).Scan(&signatureJSON); err != nil {
		t.Fatal(err)
	}
	if signatureJSON != `{"state":"future"}` {
		t.Fatalf("failed current-schema open rewrote signature facts to %q", signatureJSON)
	}
}

func TestSQLiteRegistryRejectsTamperedCurrentReceiptWithoutRepair(t *testing.T) {
	tests := []struct {
		name       string
		setClause  string
		setArgs    []any
		selectExpr string
	}{
		{name: "snapshot package binding", setClause: `intended_package_sha256 = ?`, setArgs: []any{"sha256:tampered-package"}, selectExpr: `intended_package_sha256`},
		{name: "confirmation digest shape", setClause: `confirmation_digest = ?`, setArgs: []any{"sha256:short"}, selectExpr: `confirmation_digest`},
		{name: "snapshot updated time binding", setClause: `updated_at = updated_at + 1`, selectExpr: `updated_at`},
		{name: "committing empty snapshot", setClause: `status = 'committing', mutation_outcome = 'unknown', record_snapshot_json = ?`, setArgs: []any{""}, selectExpr: `record_snapshot_json`},
		{name: "committing whitespace snapshot", setClause: `status = 'committing', mutation_outcome = 'unknown', record_snapshot_json = ?`, setArgs: []any{" "}, selectExpr: `record_snapshot_json`},
		{name: "committing malformed snapshot", setClause: `status = 'committing', mutation_outcome = 'unknown', record_snapshot_json = ?`, setArgs: []any{"{"}, selectExpr: `record_snapshot_json`},
		{name: "committing noncanonical null snapshot", setClause: `status = 'committing', mutation_outcome = 'unknown', record_snapshot_json = ?`, setArgs: []any{" null "}, selectExpr: `record_snapshot_json`},
		{name: "committed nonobject snapshot", setClause: `record_snapshot_json = ?`, setArgs: []any{"[]"}, selectExpr: `record_snapshot_json`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := registryTestContext()
			path := filepath.Join(t.TempDir(), "registry.sqlite")
			store, err := NewSQLiteStore(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			req := externalPackageInstallRequest("owner_env_hash_test", time.Now().UTC())
			if _, err := store.CommitExternalPackage(ctx, req); err != nil {
				t.Fatal(err)
			}
			args := append(append([]any{}, test.setArgs...), "owner_env_hash_test", req.InspectionID)
			if _, err := store.db.ExecContext(ctx, `UPDATE external_package_commit_receipts SET `+test.setClause+` WHERE owner_env_hash = ? AND inspection_id = ?`, args...); err != nil {
				t.Fatal(err)
			}
			var tamperedValue string
			if err := store.db.QueryRowContext(ctx, `SELECT CAST(`+test.selectExpr+` AS TEXT) FROM external_package_commit_receipts WHERE owner_env_hash = ? AND inspection_id = ?`, "owner_env_hash_test", req.InspectionID).Scan(&tamperedValue); err != nil {
				t.Fatal(err)
			}
			if _, err := store.QueryExternalPackageCommit(ctx, QueryExternalPackageCommitRequest{InspectionID: req.InspectionID, CommitID: req.CommitID}); err == nil {
				t.Fatal("QueryExternalPackageCommit() accepted a tampered receipt")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := NewSQLiteStore(ctx, path); err == nil {
				_ = reopened.Close()
				t.Fatal("NewSQLiteStore() accepted a tampered current receipt")
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
			var persistedValue string
			if err := db.QueryRowContext(ctx, `SELECT CAST(`+test.selectExpr+` AS TEXT) FROM external_package_commit_receipts WHERE owner_env_hash = ? AND inspection_id = ?`, "owner_env_hash_test", req.InspectionID).Scan(&persistedValue); err != nil {
				t.Fatal(err)
			}
			if persistedValue != tamperedValue {
				t.Fatalf("failed current-schema open rewrote receipt value from %q to %q", tamperedValue, persistedValue)
			}
		})
	}
}

func TestSQLiteRegistryMigratesUnversionedExternalFactsAndPreservesRecords(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.PutPlugin(ctx, PluginRecord{
		PluginInstanceID: "plugini_external_migration", PublisherID: "example",
		PluginID: "com.example.external-migration", Version: "1.0.0",
		PackageHash: "sha256:legacy-package", TrustState: TrustVerified,
		TrustAssessment: TrustAssessment{TrustState: TrustVerified, VerifiedSignature: &VerifiedSignature{Algorithm: "ed25519", KeyID: "legacy-key"}},
		EnableState:     EnableDisabled,
		Manifest:        manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.external-migration", Version: "1.0.0"}},
	}, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `ALTER TABLE plugin_records DROP COLUMN signature_assessment_json`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TABLE external_package_commit_receipts`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	got, err := migrated.GetPlugin(ctx, record.PluginInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SignatureAssessment.Status != SignatureVerified || got.SignatureAssessment.KeyID != "legacy-key" {
		t.Fatalf("migrated signature assessment = %#v", got.SignatureAssessment)
	}
	var version int
	if err := migrated.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != registrySQLiteSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, registrySQLiteSchemaVersion)
	}
}

func TestSQLiteRegistryV0MigrationPreservesMultipleOwnersAndVersionFacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	owners := []string{"owner_env_a", "owner_env_b"}
	for _, owner := range owners {
		ctx := registryTestContextFor("user_"+owner, owner)
		packageHash := "sha256:package-" + owner
		record, err := store.PutPlugin(ctx, PluginRecord{
			PluginInstanceID: "plugini_shared", PublisherID: "example", PluginID: "com.example.shared",
			Version: "2.0.0", PackageHash: packageHash, ManifestHash: "sha256:manifest-" + owner,
			EntriesHash: "sha256:entries-" + owner, TrustState: TrustVerified, EnableState: EnableDisabled,
			Manifest: manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.shared", Version: "2.0.0"}},
			VersionHistory: []PluginVersion{{
				Version: "1.0.0", PackageHash: "sha256:history-package-" + owner,
				ManifestHash: "sha256:history-manifest-" + owner, EntriesHash: "sha256:history-entries-" + owner,
				TrustState: TrustVerified,
			}},
		}, PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if record.OwnerEnvHash != owner {
			t.Fatalf("stored owner = %q, want %q", record.OwnerEnvHash, owner)
		}
	}
	if _, err := store.db.ExecContext(context.Background(), `ALTER TABLE plugin_records DROP COLUMN signature_assessment_json`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DROP TABLE external_package_commit_receipts`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := NewSQLiteStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	for _, owner := range owners {
		ctx := registryTestContextFor("user_"+owner, owner)
		record, err := migrated.GetPlugin(ctx, "plugini_shared")
		if err != nil {
			t.Fatal(err)
		}
		if record.OwnerEnvHash != owner || record.PackageHash != "sha256:package-"+owner {
			t.Fatalf("migrated record for %q = %#v", owner, record)
		}
		if len(record.VersionHistory) != 1 {
			t.Fatalf("migrated history for %q = %#v", owner, record.VersionHistory)
		}
		version := record.VersionHistory[0]
		if version.ManifestHash != "sha256:history-manifest-"+owner || version.EntriesHash != "sha256:history-entries-"+owner {
			t.Fatalf("migrated version hashes for %q = %#v", owner, version)
		}
		if version.SignatureAssessment.AssessedHashes.ManifestSHA256 != version.ManifestHash ||
			version.SignatureAssessment.AssessedHashes.EntriesSHA256 != version.EntriesHash ||
			version.ExecutionApproval.OwnerEnvHash != owner {
			t.Fatalf("migrated version security facts for %q = %#v", owner, version)
		}
	}
}

func TestSQLiteRegistryRejectsCurrentSchemaDriftWithoutRepair(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TABLE external_package_commit_receipts`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewSQLiteStore(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() repaired a missing current-schema table")
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
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'external_package_commit_receipts'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed current-schema open recreated the missing table")
	}
}

func TestSQLiteRegistryRollsBackFailedExternalFactsMigration(t *testing.T) {
	ctx := registryTestContext()
	path := filepath.Join(t.TempDir(), "registry.sqlite")
	store, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.PutPlugin(ctx, PluginRecord{
		PluginInstanceID: "plugini_external_rollback", PublisherID: "example",
		PluginID: "com.example.external-rollback", Version: "1.0.0",
		TrustState: TrustVerified, EnableState: EnableDisabled,
		Manifest: manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.external-rollback", Version: "1.0.0"}},
	}, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `ALTER TABLE plugin_records DROP COLUMN signature_assessment_json`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TABLE external_package_commit_receipts`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE plugin_records SET trust_assessment_json = '{' WHERE plugin_instance_id = ?`, record.PluginInstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewSQLiteStore(ctx, path); err == nil {
		_ = reopened.Close()
		t.Fatal("NewSQLiteStore() accepted invalid legacy trust JSON")
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
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("failed migration changed schema version to %d", version)
	}
	var columnCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('plugin_records') WHERE name = 'signature_assessment_json'`).Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != 0 {
		t.Fatal("failed migration retained a partially added column")
	}
}

func externalPackageInstallRequest(ownerEnvHash string, now time.Time) CommitExternalPackageRequest {
	packageHash := "sha256:external-package"
	return CommitExternalPackageRequest{
		InspectionID:          "inspect_external_package",
		CommitID:              "commit_external_package",
		Intent:                ExternalPackageInstall,
		ConfirmationDigest:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		IntendedFingerprint:   "sha256:external-fingerprint",
		IntendedPackageSHA256: packageHash,
		Now:                   now,
		Record: PluginRecord{
			PluginInstanceID:  "plugini_external",
			PublisherID:       "example",
			PluginID:          "com.example.external",
			Version:           "1.0.0",
			ActiveFingerprint: "sha256:external-fingerprint",
			PackageHash:       packageHash,
			ManifestHash:      "sha256:manifest",
			EntriesHash:       "sha256:entries",
			TrustState:        TrustNeedsReview,
			SignatureAssessment: SignatureAssessment{
				Status: SignatureAbsent,
				AssessedHashes: TrustHashSet{
					PackageSHA256: packageHash, ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries",
				},
				PackageSHA256: packageHash, ManifestSHA256: "sha256:manifest", EntriesSHA256: "sha256:entries",
			},
			PackageSourceProvenance: PackageSourceProvenance{
				Kind: PackageSourceGitHubRepository, RepositoryURL: "https://github.com/example/plugin",
				GitHubRepositoryID: "R_123", GitHubReleaseID: "REL_123", GitHubAssetID: "ASSET_123",
				PackageSHA256: packageHash,
			},
			ExecutionApproval: ExecutionApproval{
				Status: ExecutionApprovalUserApproved, OwnerEnvHash: ownerEnvHash, PackageSHA256: packageHash,
			},
			UpdateEligibility: UpdateManualOnly,
			SecurityCapabilitySummary: SecurityCapabilitySummary{
				SchemaVersion: "security-capability-summary-v1", CanonicalJSON: `{"network":false}`,
				SHA256: "sha256:capability-summary",
			},
			EnableState: EnableDisabled,
			Manifest:    manifest.Manifest{Plugin: manifest.Plugin{PluginID: "com.example.external", Version: "1.0.0"}},
		},
	}
}
