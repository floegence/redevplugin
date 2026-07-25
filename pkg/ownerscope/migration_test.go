//go:build darwin || linux

package ownerscope

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenOwnerScopeMigrationPreparesFreshInstallOnlyForEmptyRoot(t *testing.T) {
	rootPath := t.TempDir()
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	status := migration.Status()
	if status.State != StateFreshPrepared || status.InventoryID != "" || status.FreshGenerationID == "" {
		t.Fatalf("fresh status = %#v", status)
	}
	committed, err := migration.CommitFreshGeneration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateFreshCommitted || committed.FreshGenerationID != status.FreshGenerationID {
		t.Fatalf("committed status = %#v", committed)
	}
	assertMigrationJournalExists(t, rootPath)
}

func TestPrepareOwnerScopeGenerationAutomaticallyMigratesLegacyState(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)

	generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if generation.Status.State != StateFreshCommitted || generation.Status.QuarantineID.IsZero() {
		t.Fatalf("prepared generation status = %#v", generation.Status)
	}
	if generation.Path == "" {
		t.Fatal("prepared generation path is empty")
	}
	quarantinedAsset := filepath.Join(rootPath, quarantineDirectory, generation.Status.QuarantineID.String(), "assets", "package.bin")
	if raw, err := os.ReadFile(quarantinedAsset); err != nil || string(raw) != "asset" {
		t.Fatalf("quarantined legacy asset = %q, %v", raw, err)
	}
	statePath := filepath.Join(generation.Path, "db", "registry.sqlite")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("owned state"), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Path != generation.Path || reopened.Status.FreshGenerationID != generation.Status.FreshGenerationID {
		t.Fatalf("reopened generation = %#v, want path %q and id %q", reopened, generation.Path, generation.Status.FreshGenerationID)
	}
	if raw, err := os.ReadFile(filepath.Join(reopened.Path, "db", "registry.sqlite")); err != nil || string(raw) != "owned state" {
		t.Fatalf("reopened active state = %q, %v", raw, err)
	}
	if raw, err := os.ReadFile(quarantinedAsset); err != nil || string(raw) != "asset" {
		t.Fatalf("retained quarantine after reopen = %q, %v", raw, err)
	}
}

func TestPrepareOwnerScopeGenerationMigratesLegacyStateWithV065TrustOverlay(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	trustPath := filepath.Join(rootPath, "trust", "trusted-time", "marker")
	if err := os.MkdirAll(filepath.Dir(trustPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, []byte("trust-overlay"), 0o600); err != nil {
		t.Fatal(err)
	}

	generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if generation.Status.InventoryID != RedevenLegacyInventoryV1 || generation.Status.State != StateFreshCommitted {
		t.Fatalf("prepared generation status = %#v", generation.Status)
	}
	quarantinedTrust := filepath.Join(rootPath, quarantineDirectory, generation.Status.QuarantineID.String(), "trust", "trusted-time", "marker")
	if raw, err := os.ReadFile(quarantinedTrust); err != nil || string(raw) != "trust-overlay" {
		t.Fatalf("quarantined trust overlay = %q, %v", raw, err)
	}

	reopened, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Path != generation.Path || reopened.Status.FreshGenerationID != generation.Status.FreshGenerationID {
		t.Fatalf("reopened generation = %#v, want path %q and id %q", reopened, generation.Path, generation.Status.FreshGenerationID)
	}
	if raw, err := os.ReadFile(quarantinedTrust); err != nil || string(raw) != "trust-overlay" {
		t.Fatalf("retained trust overlay = %q, %v", raw, err)
	}
}

func TestPrepareOwnerScopeGenerationCommitsFreshInstall(t *testing.T) {
	rootPath := t.TempDir()
	generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if generation.Status.State != StateFreshCommitted || generation.Status.FreshGenerationID == "" || !generation.Status.QuarantineID.IsZero() {
		t.Fatalf("fresh generation status = %#v", generation.Status)
	}
	if info, err := os.Stat(generation.Path); err != nil || !info.IsDir() {
		t.Fatalf("fresh generation path stat = %#v, %v", info, err)
	}
}

func TestPrepareOwnerScopeGenerationRebindsRelocatedCommittedGeneration(t *testing.T) {
	sourceRoot := t.TempDir()
	writeRedevenLegacyInventory(t, sourceRoot)
	generation, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	activeMarker := filepath.Join(generation.Path, "storage", "created-after-migration")
	if err := os.MkdirAll(filepath.Dir(activeMarker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activeMarker, []byte("active"), 0o600); err != nil {
		t.Fatal(err)
	}

	relocatedRoot := moveOwnerScopeRootContents(t, sourceRoot)
	journalPath := filepath.Join(relocatedRoot, MigrationJournalName)
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := PrepareOwnerScopeGeneration(context.Background(), relocatedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status.FreshGenerationID != generation.Status.FreshGenerationID || reopened.Status.QuarantineID != generation.Status.QuarantineID {
		t.Fatalf("relocated generation = %#v, want ids from %#v", reopened, generation)
	}
	if reopened.Status.RootIdentitySHA256 == generation.Status.RootIdentitySHA256 {
		t.Fatal("relocated generation retained the source root identity")
	}
	if raw, err := os.ReadFile(filepath.Join(reopened.Path, "storage", "created-after-migration")); err != nil || string(raw) != "active" {
		t.Fatalf("relocated active state = %q, %v", raw, err)
	}
	quarantinedAsset := filepath.Join(relocatedRoot, quarantineDirectory, reopened.Status.QuarantineID.String(), "assets", "package.bin")
	if raw, err := os.ReadFile(quarantinedAsset); err != nil || string(raw) != "asset" {
		t.Fatalf("relocated quarantine = %q, %v", raw, err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(after, before) {
		t.Fatal("relocated journal did not commit the new root identity")
	}

	idempotent, err := PrepareOwnerScopeGeneration(context.Background(), relocatedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.Path != reopened.Path || idempotent.Status.RootIdentitySHA256 != reopened.Status.RootIdentitySHA256 {
		t.Fatalf("idempotent relocated generation = %#v, want %#v", idempotent, reopened)
	}
	stable, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stable, after) {
		t.Fatal("idempotent reopen rewrote the relocated journal")
	}
}

func TestPrepareOwnerScopeGenerationRebindsRelocatedFreshInstall(t *testing.T) {
	sourceRoot := t.TempDir()
	generation, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	relocatedRoot := copyOwnerScopeRoot(t, sourceRoot)
	reopened, err := PrepareOwnerScopeGeneration(context.Background(), relocatedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status.FreshGenerationID != generation.Status.FreshGenerationID || !reopened.Status.QuarantineID.IsZero() {
		t.Fatalf("relocated fresh generation = %#v, want %#v", reopened, generation)
	}
}

func TestPrepareOwnerScopeGenerationRejectsUnsafeRelocationWithoutMutation(t *testing.T) {
	t.Run("incomplete migration", func(t *testing.T) {
		sourceRoot := t.TempDir()
		root := openMigrationRoot(t, sourceRoot)
		migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
		root.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := migration.Close(); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := copyOwnerScopeRoot(t, sourceRoot)
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("changed active marker", func(t *testing.T) {
		sourceRoot := t.TempDir()
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := copyOwnerScopeRoot(t, sourceRoot)
		if err := os.WriteFile(filepath.Join(relocatedRoot, currentGenerationFile), []byte("generation_00000000000000000000000000000000\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("copied fresh active state", func(t *testing.T) {
		sourceRoot := t.TempDir()
		generation, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(generation.Path, "plugin-state"), []byte("untrusted after copy"), 0o600); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := copyOwnerScopeRoot(t, sourceRoot)
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("unexpected quarantine entry", func(t *testing.T) {
		sourceRoot := t.TempDir()
		writeRedevenLegacyInventory(t, sourceRoot)
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := moveOwnerScopeRootContents(t, sourceRoot)
		if err := os.Mkdir(filepath.Join(relocatedRoot, quarantineDirectory, "quarantine_00000000000000000000000000000000"), 0o700); err != nil {
			t.Fatal(err)
		}
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("copied committed quarantine", func(t *testing.T) {
		sourceRoot := t.TempDir()
		writeRedevenLegacyInventory(t, sourceRoot)
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := copyOwnerScopeRoot(t, sourceRoot)
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("tampered store outcome", func(t *testing.T) {
		sourceRoot := t.TempDir()
		writeRedevenLegacyInventory(t, sourceRoot)
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := moveOwnerScopeRootContents(t, sourceRoot)
		journalPath := filepath.Join(relocatedRoot, MigrationJournalName)
		raw, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := decodeMigrationJournal(raw)
		if err != nil {
			t.Fatal(err)
		}
		journal.Stores[0].Outcome = "changed"
		tampered, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(journalPath, append(tampered, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("tampered inventory digest", func(t *testing.T) {
		sourceRoot := t.TempDir()
		writeRedevenLegacyInventory(t, sourceRoot)
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := moveOwnerScopeRootContents(t, sourceRoot)
		journalPath := filepath.Join(relocatedRoot, MigrationJournalName)
		raw, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := decodeMigrationJournal(raw)
		if err != nil {
			t.Fatal(err)
		}
		journal.InventorySHA256 = digestString("changed inventory")
		tampered, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(journalPath, append(tampered, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("tampered fresh digest", func(t *testing.T) {
		sourceRoot := t.TempDir()
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := moveOwnerScopeRootContents(t, sourceRoot)
		journalPath := filepath.Join(relocatedRoot, MigrationJournalName)
		raw, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := decodeMigrationJournal(raw)
		if err != nil {
			t.Fatal(err)
		}
		journal.FreshGenerationSHA256 = digestString("changed generation")
		tampered, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(journalPath, append(tampered, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRelocationRejectedWithoutJournalMutation(t, relocatedRoot)
	})

	t.Run("active cleanup transaction", func(t *testing.T) {
		sourceRoot := t.TempDir()
		writeRedevenLegacyInventory(t, sourceRoot)
		if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
			t.Fatal(err)
		}
		root := openMigrationRoot(t, sourceRoot)
		migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
		root.Close()
		if err != nil {
			t.Fatal(err)
		}
		parent, err := openDirectoryAt(int(migration.root.Fd()), quarantineDirectory)
		if err != nil {
			t.Fatal(err)
		}
		quarantine, err := openDirectoryAt(int(parent.Fd()), migration.journal.QuarantineID)
		parent.Close()
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := snapshotDirectory(quarantine)
		quarantine.Close()
		if err != nil {
			t.Fatal(err)
		}
		cleanup := cleanupJournalV1{
			SchemaVersion: cleanupSchemaVersion, MigrationID: migration.journal.MigrationID,
			RootIdentitySHA256: migration.journal.RootIdentitySHA256, QuarantineID: migration.journal.QuarantineID,
			QuarantineSHA256: migration.journal.QuarantineSHA256, State: string(CleanupStateDeletePrepared), Entries: snapshot.entries,
		}
		if err := migration.persistCleanup(cleanup); err != nil {
			t.Fatal(err)
		}
		if err := migration.Close(); err != nil {
			t.Fatal(err)
		}
		relocatedRoot := moveOwnerScopeRootContents(t, sourceRoot)
		journalBefore, err := os.ReadFile(filepath.Join(relocatedRoot, MigrationJournalName))
		if err != nil {
			t.Fatal(err)
		}
		cleanupBefore, err := os.ReadFile(filepath.Join(relocatedRoot, CleanupJournalName))
		if err != nil {
			t.Fatal(err)
		}
		if generation, err := PrepareOwnerScopeGeneration(context.Background(), relocatedRoot); generation.Path != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
			t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
		}
		journalAfter, _ := os.ReadFile(filepath.Join(relocatedRoot, MigrationJournalName))
		cleanupAfter, _ := os.ReadFile(filepath.Join(relocatedRoot, CleanupJournalName))
		if !bytes.Equal(journalAfter, journalBefore) || !bytes.Equal(cleanupAfter, cleanupBefore) {
			t.Fatal("rejected cleanup relocation mutated its journals")
		}
	})
}

func TestRecoverOwnerScopeRootArchivesCopiedStateAndCommitsFreshGeneration(t *testing.T) {
	sourceRoot := t.TempDir()
	writeRedevenLegacyInventory(t, sourceRoot)
	sourceGeneration, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	activeMarker := filepath.Join(sourceGeneration.Path, "storage", "user-state")
	if err := os.MkdirAll(filepath.Dir(activeMarker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activeMarker, []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}

	recoveryRoot := copyOwnerScopeRoot(t, sourceRoot)
	before, err := snapshotPath(t, recoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := InspectOwnerScopeRootRecovery(recoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PlanSHA256 == "" || plan.SourceSnapshotSHA256 != before.digest || !plan.HasRetainedQuarantine || plan.SourceEntryCount != len(before.entries) {
		t.Fatalf("recovery plan = %#v, snapshot = %#v", plan, before)
	}
	readOnly, err := snapshotPath(t, recoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if readOnly.digest != before.digest {
		t.Fatal("recovery inspection mutated the source root")
	}
	if result, err := RecoverOwnerScopeRoot(context.Background(), recoveryRoot, digestString("wrong plan")); result.State != "" || !errors.Is(err, ErrOwnerScopeRecoveryPlanMismatch) {
		t.Fatalf("wrong-plan recovery = %#v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(recoveryRoot, RootRecoveryJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-plan recovery wrote a journal: %v", err)
	}

	result, err := RecoverOwnerScopeRoot(context.Background(), recoveryRoot, plan.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != RootRecoveryStateFreshCommitted || result.ArchivePath == "" || result.Generation.Path == "" || result.Generation.Status.FreshGenerationID == sourceGeneration.Status.FreshGenerationID {
		t.Fatalf("recovery result = %#v", result)
	}
	archive := openMigrationRoot(t, result.ArchivePath)
	archiveSnapshot, err := snapshotDirectory(archive)
	archive.Close()
	if err != nil {
		t.Fatal(err)
	}
	if archiveSnapshot.digest != plan.SourceSnapshotSHA256 || len(archiveSnapshot.entries) != plan.SourceEntryCount {
		t.Fatalf("archive snapshot = %#v, plan = %#v", archiveSnapshot, plan)
	}
	archivedMarker := filepath.Join(result.ArchivePath, generationsDirectory, sourceGeneration.Status.FreshGenerationID, "storage", "user-state")
	if raw, err := os.ReadFile(archivedMarker); err != nil || string(raw) != "retained" {
		t.Fatalf("archived user state = %q, %v", raw, err)
	}
	newGenerationEntries, err := os.ReadDir(result.Generation.Path)
	if err != nil || len(newGenerationEntries) != 0 {
		t.Fatalf("new generation entries = %#v, %v", newGenerationEntries, err)
	}

	prepared, err := PrepareOwnerScopeGeneration(context.Background(), recoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Path != result.Generation.Path || prepared.Status.FreshGenerationID != result.Generation.Status.FreshGenerationID {
		t.Fatalf("prepared recovered generation = %#v, want %#v", prepared, result.Generation)
	}
	idempotent, err := RecoverOwnerScopeRoot(context.Background(), recoveryRoot, plan.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.RecoveryID != result.RecoveryID || idempotent.ArchivePath != result.ArchivePath || idempotent.Generation.Path != result.Generation.Path {
		t.Fatalf("idempotent recovery = %#v, want %#v", idempotent, result)
	}

	root := openMigrationRoot(t, recoveryRoot)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{Containment: acceptingContainmentVerifier{}})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	if _, err := migration.DeleteQuarantine(context.Background()); !errors.Is(err, ErrOwnerScopeRecoveryArchiveRetained) {
		t.Fatalf("DeleteQuarantine() error = %v", err)
	}
	if raw, err := os.ReadFile(archivedMarker); err != nil || string(raw) != "retained" {
		t.Fatalf("retained archive after cleanup attempt = %q, %v", raw, err)
	}
}

func TestRecoverOwnerScopeRootResumesEveryPersistedStage(t *testing.T) {
	for _, stage := range []string{
		"prepared", "archive-writing", "work-created", "archive-partial", "archive-renamed", "archive-committed",
		"fresh-prepared", "fresh-parent", "fresh-generation", "fresh-artifacts", "standard-journal-committed", "fresh-committed",
	} {
		t.Run(stage, func(t *testing.T) {
			rootPath, plan, journal := prepareRecoveryFixture(t)
			root := openMigrationRoot(t, rootPath)
			switch stage {
			case "prepared":
			case "archive-writing":
				journal.State = string(RootRecoveryStateArchiveWriting)
				mustPersistRecoveryJournal(t, root, journal)
			case "work-created":
				journal.State = string(RootRecoveryStateArchiveWriting)
				mustPersistRecoveryJournal(t, root, journal)
				if err := ensureDirectoryAt(int(root.Fd()), rootRecoveryWorkDirectory, 0o700); err != nil {
					t.Fatal(err)
				}
			case "archive-partial":
				journal.State = string(RootRecoveryStateArchiveWriting)
				mustPersistRecoveryJournal(t, root, journal)
				archive := prepareRecoveryWorkArchive(t, root, journal)
				if err := moveStoreIntoQuarantine(int(root.Fd()), int(archive.Fd()), journal.TopLevelEntries[0]); err != nil {
					t.Fatal(err)
				}
				archive.Close()
			case "archive-renamed":
				journal.State = string(RootRecoveryStateArchiveWriting)
				mustPersistRecoveryJournal(t, root, journal)
				if err := writeRecoveryArchive(root, &journal); err != nil {
					t.Fatal(err)
				}
				journal.State = string(RootRecoveryStateArchiveWriting)
				journal.QuarantineSHA256 = ""
				journal.QuarantineContentSHA256 = ""
				mustPersistRecoveryJournal(t, root, journal)
			case "archive-committed":
				journal.State = string(RootRecoveryStateArchiveWriting)
				mustPersistRecoveryJournal(t, root, journal)
				if err := writeRecoveryArchive(root, &journal); err != nil {
					t.Fatal(err)
				}
			case "fresh-prepared", "fresh-parent", "fresh-generation", "fresh-artifacts", "standard-journal-committed":
				journal.State = string(RootRecoveryStateArchiveWriting)
				mustPersistRecoveryJournal(t, root, journal)
				if err := writeRecoveryArchive(root, &journal); err != nil {
					t.Fatal(err)
				}
				journal.State = string(RootRecoveryStateFreshPrepared)
				mustPersistRecoveryJournal(t, root, journal)
				if stage == "fresh-parent" || stage == "fresh-generation" {
					if err := ensureDirectoryAt(int(root.Fd()), generationsDirectory, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "fresh-generation" {
					generations, err := openDirectoryAt(int(root.Fd()), generationsDirectory)
					if err != nil {
						t.Fatal(err)
					}
					if err := ensureDirectoryAt(int(generations.Fd()), journal.FreshGenerationID, 0o700); err != nil {
						generations.Close()
						t.Fatal(err)
					}
					generations.Close()
				}
				if stage == "fresh-artifacts" || stage == "standard-journal-committed" {
					prepareRecoveryFreshArtifacts(t, root, journal)
				}
				if stage == "standard-journal-committed" {
					raw, err := json.Marshal(recoveredMigrationJournal(journal))
					if err != nil {
						t.Fatal(err)
					}
					if err := writeAtomicRootFile(root, MigrationJournalName, append(raw, '\n'), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "fresh-committed":
				root.Close()
				if _, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256); err != nil {
					t.Fatal(err)
				}
				root = nil
			}
			if root != nil {
				root.Close()
			}

			if _, err := PrepareOwnerScopeGeneration(context.Background(), rootPath); !errors.Is(err, ErrOwnerScopeRecoveryRequired) && stage != "fresh-committed" {
				t.Fatalf("normal preparation during %s error = %v", stage, err)
			}
			result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
			if err != nil {
				t.Fatal(err)
			}
			if result.State != RootRecoveryStateFreshCommitted {
				t.Fatalf("resumed result = %#v", result)
			}
			archive := openMigrationRoot(t, result.ArchivePath)
			snapshot, err := snapshotDirectory(archive)
			archive.Close()
			if err != nil || snapshot.digest != plan.SourceSnapshotSHA256 {
				t.Fatalf("resumed archive = %#v, %v", snapshot, err)
			}
		})
	}
}

func TestRecoverOwnerScopeRootResumesAfterEveryArchiveMove(t *testing.T) {
	for moved := 0; moved <= 3; moved++ {
		t.Run(fmt.Sprintf("moved-%d", moved), func(t *testing.T) {
			rootPath, plan, journal := prepareRecoveryFixture(t)
			root := openMigrationRoot(t, rootPath)
			journal.State = string(RootRecoveryStateArchiveWriting)
			mustPersistRecoveryJournal(t, root, journal)
			archive := prepareRecoveryWorkArchive(t, root, journal)
			for index := 0; index < moved; index++ {
				if err := moveStoreIntoQuarantine(int(root.Fd()), int(archive.Fd()), journal.TopLevelEntries[index]); err != nil {
					archive.Close()
					root.Close()
					t.Fatal(err)
				}
			}
			archive.Close()
			root.Close()
			result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
			if err != nil {
				t.Fatal(err)
			}
			if result.State != RootRecoveryStateFreshCommitted {
				t.Fatalf("resumed result = %#v", result)
			}
		})
	}
}

func TestRecoverOwnerScopeRootRejectsTamperedFreshArtifactsWithoutAuthorization(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, rootRecoveryJournalV1)
	}{
		{name: "active generation content", mutate: func(t *testing.T, rootPath string, journal rootRecoveryJournalV1) {
			path := filepath.Join(rootPath, generationsDirectory, journal.FreshGenerationID, "injected-state")
			if err := os.WriteFile(path, []byte("must not be authorized"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "additional generation", mutate: func(t *testing.T, rootPath string, _ rootRecoveryJournalV1) {
			path := filepath.Join(rootPath, generationsDirectory, "generation_00000000000000000000000000000000")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong current marker", mutate: func(t *testing.T, rootPath string, _ rootRecoveryJournalV1) {
			path := filepath.Join(rootPath, currentGenerationFile)
			if err := os.WriteFile(path, []byte("generation_00000000000000000000000000000000\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath, plan, journal := prepareRecoveryFixture(t)
			root := openMigrationRoot(t, rootPath)
			journal.State = string(RootRecoveryStateArchiveWriting)
			mustPersistRecoveryJournal(t, root, journal)
			if err := writeRecoveryArchive(root, &journal); err != nil {
				root.Close()
				t.Fatal(err)
			}
			journal.State = string(RootRecoveryStateFreshPrepared)
			mustPersistRecoveryJournal(t, root, journal)
			prepareRecoveryFreshArtifacts(t, root, journal)
			root.Close()

			test.mutate(t, rootPath, journal)
			before, err := snapshotPathExcluding(t, rootPath, map[string]struct{}{RootRecoveryJournalName: {}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
			if !errors.Is(err, ErrOwnerScopeSnapshotChanged) || result.State != RootRecoveryStateReconcileRequired || result.Generation.Path != "" {
				t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
			}
			after, err := snapshotPathExcluding(t, rootPath, map[string]struct{}{RootRecoveryJournalName: {}})
			if err != nil || after.digest != before.digest {
				t.Fatalf("rejected fresh artifacts changed root: %#v, %v", after, err)
			}
			raw := mustReadFile(t, filepath.Join(rootPath, RootRecoveryJournalName))
			persisted, err := decodeRootRecoveryJournal(raw)
			if err != nil || persisted.State != string(RootRecoveryStateReconcileRequired) {
				t.Fatalf("persisted recovery journal = %#v, %v", persisted, err)
			}
			if generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath); generation.Path != "" || !errors.Is(err, ErrOwnerScopeRecoveryRequired) {
				t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
			}
		})
	}
}

func TestRecoverOwnerScopeRootRejectsUnexpectedRootEntryBeforeCommit(t *testing.T) {
	rootPath, plan, journal := prepareRecoveryFixture(t)
	root := openMigrationRoot(t, rootPath)
	journal.State = string(RootRecoveryStateArchiveWriting)
	mustPersistRecoveryJournal(t, root, journal)
	if err := writeRecoveryArchive(root, &journal); err != nil {
		root.Close()
		t.Fatal(err)
	}
	journal.State = string(RootRecoveryStateFreshPrepared)
	mustPersistRecoveryJournal(t, root, journal)
	root.Close()
	unexpected := filepath.Join(rootPath, "unexpected-root-entry")
	if err := os.WriteFile(unexpected, []byte("must remain untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
	if !errors.Is(err, ErrOwnerScopeSnapshotChanged) || result.State != RootRecoveryStateReconcileRequired || result.Generation.Path != "" {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
	}
	if raw, err := os.ReadFile(unexpected); err != nil || string(raw) != "must remain untrusted" {
		t.Fatalf("unexpected root evidence = %q, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected recovery committed a migration journal: %v", err)
	}
	if generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath); generation.Path != "" || !errors.Is(err, ErrOwnerScopeRecoveryRequired) {
		t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
	}
}

func TestRecoveredOwnerScopeRootVerifiesRetainedArchiveOnEveryOpen(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, OwnerScopeRootRecoveryResult)
	}{
		{name: "deleted archive", mutate: func(t *testing.T, result OwnerScopeRootRecoveryResult) {
			if err := os.RemoveAll(result.ArchivePath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "additional archive", mutate: func(t *testing.T, result OwnerScopeRootRecoveryResult) {
			path := filepath.Join(filepath.Dir(result.ArchivePath), "quarantine_00000000000000000000000000000000")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "content tamper", mutate: func(t *testing.T, result OwnerScopeRootRecoveryResult) {
			path := filepath.Join(result.ArchivePath, MigrationJournalName)
			if err := os.WriteFile(path, []byte("tampered\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "inode tamper", mutate: func(t *testing.T, result OwnerScopeRootRecoveryResult) {
			path := filepath.Join(result.ArchivePath, MigrationJournalName)
			raw := mustReadFile(t, path)
			replacement := filepath.Join(result.ArchivePath, "replacement")
			if err := os.WriteFile(replacement, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink tamper", mutate: func(t *testing.T, result OwnerScopeRootRecoveryResult) {
			if err := os.Symlink(MigrationJournalName, filepath.Join(result.ArchivePath, "injected-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink tamper", mutate: func(t *testing.T, result OwnerScopeRootRecoveryResult) {
			source := filepath.Join(result.ArchivePath, MigrationJournalName)
			if err := os.Link(source, filepath.Join(result.ArchivePath, "injected-hardlink")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath, plan, _ := prepareRecoveryFixture(t)
			committed, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, committed)
			recoveryJournalBefore := mustReadFile(t, filepath.Join(rootPath, RootRecoveryJournalName))
			migrationJournalBefore := mustReadFile(t, filepath.Join(rootPath, MigrationJournalName))

			result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
			if !errors.Is(err, ErrOwnerScopeSnapshotChanged) || result.Generation.Path != "" {
				t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
			}
			if generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath); generation.Path != "" || !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
				t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
			}
			if !bytes.Equal(mustReadFile(t, filepath.Join(rootPath, RootRecoveryJournalName)), recoveryJournalBefore) ||
				!bytes.Equal(mustReadFile(t, filepath.Join(rootPath, MigrationJournalName)), migrationJournalBefore) {
				t.Fatal("rejected archive tamper mutated control journals")
			}
		})
	}
}

func TestInspectOwnerScopeRootRecoveryRejectsUnsafeAndAmbiguousRootsWithoutMutation(t *testing.T) {
	t.Run("same filesystem identity", func(t *testing.T) {
		rootPath := t.TempDir()
		if _, err := PrepareOwnerScopeGeneration(context.Background(), rootPath); err != nil {
			t.Fatal(err)
		}
		assertRecoveryInspectionRejectedWithoutMutation(t, rootPath, ErrOwnerScopeRecoveryNotEligible)
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "unexpected control entry", mutate: func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe symlink", mutate: func(t *testing.T, root string) {
			generationID := strings.TrimSpace(string(mustReadFile(t, filepath.Join(root, currentGenerationFile))))
			if err := os.Symlink(filepath.Join(root, MigrationJournalName), filepath.Join(root, generationsDirectory, generationID, "link")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "future journal", mutate: func(t *testing.T, root string) {
			path := filepath.Join(root, MigrationJournalName)
			raw := mustReadFile(t, path)
			future := bytes.Replace(raw, []byte(migrationSchemaVersion), []byte("owner-scope-migration-v99"), 1)
			if err := os.WriteFile(path, future, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "cleanup transaction", mutate: func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, CleanupJournalName), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			if _, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot); err != nil {
				t.Fatal(err)
			}
			rootPath := copyOwnerScopeRoot(t, sourceRoot)
			test.mutate(t, rootPath)
			assertRecoveryInspectionRejectedWithoutMutation(t, rootPath, ErrOwnerScopeRecoveryNotEligible)
		})
	}
}

func TestRecoverOwnerScopeRootRejectsPlanDriftWithoutStartingTransaction(t *testing.T) {
	sourceRoot := t.TempDir()
	generation, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := copyOwnerScopeRoot(t, sourceRoot)
	plan, err := InspectOwnerScopeRootRecovery(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	generationID := strings.TrimSpace(string(mustReadFile(t, filepath.Join(rootPath, currentGenerationFile))))
	drift := filepath.Join(rootPath, generationsDirectory, generationID, "drift")
	if err := os.WriteFile(drift, []byte("changed after inspection"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = generation
	before, err := snapshotPath(t, rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256); result.State != "" || !errors.Is(err, ErrOwnerScopeRecoveryPlanMismatch) {
		t.Fatalf("drifted recovery = %#v, %v", result, err)
	}
	after, err := snapshotPath(t, rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.digest != before.digest {
		t.Fatal("plan-drift rejection mutated the root")
	}
	if _, err := os.Stat(filepath.Join(rootPath, RootRecoveryJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plan-drift rejection wrote a recovery journal: %v", err)
	}
}

func TestRecoverOwnerScopeRootRejectsRootIdentityChangeAfterInspection(t *testing.T) {
	sourceRoot := t.TempDir()
	generation, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generation.Path, "state"), []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspectedRoot := copyOwnerScopeRoot(t, sourceRoot)
	plan, err := InspectOwnerScopeRootRecovery(inspectedRoot)
	if err != nil || plan.RootIdentitySHA256 == "" {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", plan, err)
	}
	replacedRoot := moveOwnerScopeRootContents(t, inspectedRoot)
	before, err := snapshotPath(t, replacedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := RecoverOwnerScopeRoot(context.Background(), replacedRoot, plan.PlanSHA256); result.State != "" || !errors.Is(err, ErrOwnerScopeRecoveryPlanMismatch) {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
	}
	after, err := snapshotPath(t, replacedRoot)
	if err != nil || after.digest != before.digest {
		t.Fatalf("identity drift rejection changed root: %#v, %v", after, err)
	}
	if _, err := os.Stat(filepath.Join(replacedRoot, RootRecoveryJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity drift wrote recovery journal: %v", err)
	}
}

func TestRecoverOwnerScopeRootReopensLexicalPathBeforeReturning(t *testing.T) {
	rootPath, plan, _ := prepareRecoveryFixture(t)
	movedPath := rootPath + "-moved"
	var hookErr error
	recoveryBeforePathReopenHook = func() {
		recoveryBeforePathReopenHook = nil
		if err := os.Rename(rootPath, movedPath); err != nil {
			hookErr = err
			return
		}
		hookErr = os.Mkdir(rootPath, 0o700)
	}
	defer func() { recoveryBeforePathReopenHook = nil }()
	result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if !errors.Is(err, ErrOwnerScopeSnapshotChanged) || result.Generation.Path != "" {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
	}
	prepared, err := PrepareOwnerScopeGeneration(context.Background(), movedPath)
	if err != nil || prepared.Path == "" {
		t.Fatalf("moved transaction root = %#v, %v", prepared, err)
	}
}

func TestPrepareOwnerScopeGenerationRebindsMovedRecoveredRoot(t *testing.T) {
	rootPath, plan, _ := prepareRecoveryFixture(t)
	committed, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	movedRoot := moveOwnerScopeRootContents(t, rootPath)
	prepared, err := PrepareOwnerScopeGeneration(context.Background(), movedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Status.FreshGenerationID != committed.Generation.Status.FreshGenerationID || prepared.Path == committed.Generation.Path {
		t.Fatalf("rebound generation = %#v, committed = %#v", prepared, committed.Generation)
	}
	recovery := mustReadRecoveryJournal(t, movedRoot)
	migration := mustReadMigrationJournal(t, movedRoot)
	if recovery.State != string(RootRecoveryStateFreshCommitted) || recovery.RebindRootIdentitySHA256 != "" ||
		recovery.RootIdentitySHA256 != migration.RootIdentitySHA256 || recovery.SourceRootIdentitySHA256 != plan.RootIdentitySHA256 ||
		recovery.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("rebound journals = %#v / %#v", recovery, migration)
	}
}

func TestInspectAndRecoverMovedRecoveredRootRebindsWithCurrentPlan(t *testing.T) {
	rootPath, originalPlan, _ := prepareRecoveryFixture(t)
	if _, err := RecoverOwnerScopeRoot(context.Background(), rootPath, originalPlan.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	movedRoot := moveOwnerScopeRootContents(t, rootPath)
	plan, err := InspectOwnerScopeRootRecovery(movedRoot)
	if err != nil || plan.RootIdentitySHA256 == "" || plan.RootIdentitySHA256 == originalPlan.RootIdentitySHA256 || plan.PlanSHA256 == originalPlan.PlanSHA256 {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", plan, err)
	}
	result, err := RecoverOwnerScopeRoot(context.Background(), movedRoot, plan.PlanSHA256)
	if err != nil || result.Generation.Path == "" || result.Plan.PlanSHA256 != plan.PlanSHA256 || result.Plan.RootIdentitySHA256 != plan.RootIdentitySHA256 {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
	}
	idempotent, err := RecoverOwnerScopeRoot(context.Background(), movedRoot, plan.PlanSHA256)
	if err != nil || idempotent.Generation.Path != result.Generation.Path {
		t.Fatalf("idempotent RecoverOwnerScopeRoot() = %#v, %v", idempotent, err)
	}
}

func TestRecoverOwnerScopeRootExplicitlyRecoversFileCopiedRecoveredRoot(t *testing.T) {
	rootPath, plan, _ := prepareRecoveryFixture(t)
	first, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	activeMarker := filepath.Join(first.Generation.Path, "state-created-after-first-recovery")
	if err := os.WriteFile(activeMarker, []byte("must remain archived"), 0o600); err != nil {
		t.Fatal(err)
	}
	copyRoot := copyOwnerScopeRoot(t, rootPath)
	secondPlan, err := InspectOwnerScopeRootRecovery(copyRoot)
	if err != nil || !secondPlan.HasSourceRecoveryJournal || secondPlan.SourceRecoveryJournalSHA256 == "" {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", secondPlan, err)
	}
	second, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, secondPlan.PlanSHA256)
	if err != nil || second.Generation.Path == "" || second.Generation.Status.FreshGenerationID == first.Generation.Status.FreshGenerationID {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", second, err)
	}
	entries, err := os.ReadDir(second.Generation.Path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("second fresh generation entries = %#v, %v", entries, err)
	}
	archivedMarker := filepath.Join(second.ArchivePath, generationsDirectory, first.Generation.Status.FreshGenerationID, "state-created-after-first-recovery")
	if raw, err := os.ReadFile(archivedMarker); err != nil || string(raw) != "must remain archived" {
		t.Fatalf("archived active state = %q, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(second.ArchivePath, RootRecoverySourceJournalName)); err != nil {
		t.Fatalf("archived source recovery journal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(second.ArchivePath, quarantineDirectory, first.Generation.Status.QuarantineID.String())); err != nil {
		t.Fatalf("nested retained archive: %v", err)
	}
	idempotent, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, secondPlan.PlanSHA256)
	if err != nil || idempotent.Generation.Path != second.Generation.Path {
		t.Fatalf("idempotent RecoverOwnerScopeRoot() = %#v, %v", idempotent, err)
	}
}

func TestRecoverOwnerScopeRootResumesNestedJournalRotationStages(t *testing.T) {
	for _, stage := range []string{"pending-written", "source-renamed", "canonical-rotated"} {
		t.Run(stage, func(t *testing.T) {
			copyRoot, plan, journal := prepareFileCopiedRecoveredRoot(t)
			root := openMigrationRoot(t, copyRoot)
			if err := persistRootRecoveryJournalNamed(root, RootRecoveryPendingJournalName, journal); err != nil {
				root.Close()
				t.Fatal(err)
			}
			if stage == "source-renamed" || stage == "canonical-rotated" {
				if err := os.Rename(filepath.Join(copyRoot, RootRecoveryJournalName), filepath.Join(copyRoot, RootRecoverySourceJournalName)); err != nil {
					root.Close()
					t.Fatal(err)
				}
			}
			if stage == "canonical-rotated" {
				if err := os.Rename(filepath.Join(copyRoot, RootRecoveryPendingJournalName), filepath.Join(copyRoot, RootRecoveryJournalName)); err != nil {
					root.Close()
					t.Fatal(err)
				}
			}
			root.Close()

			inspected, err := InspectOwnerScopeRootRecovery(copyRoot)
			if err != nil || inspected.PlanSHA256 != plan.PlanSHA256 {
				t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
			}
			result, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, plan.PlanSHA256)
			if err != nil || result.Generation.Path == "" {
				t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
			}
			if _, err := os.Stat(filepath.Join(result.ArchivePath, RootRecoverySourceJournalName)); err != nil {
				t.Fatalf("archived source recovery journal: %v", err)
			}
			if _, err := os.Stat(filepath.Join(copyRoot, RootRecoveryPendingJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pending recovery journal remains after commit: %v", err)
			}
		})
	}
}

func TestRecoverOwnerScopeRootRejectsAmbiguousNestedJournalRotation(t *testing.T) {
	copyRoot, plan, journal := prepareFileCopiedRecoveredRoot(t)
	root := openMigrationRoot(t, copyRoot)
	if err := persistRootRecoveryJournalNamed(root, RootRecoveryPendingJournalName, journal); err != nil {
		root.Close()
		t.Fatal(err)
	}
	sourceRaw := mustReadFile(t, filepath.Join(copyRoot, RootRecoveryJournalName))
	if err := os.WriteFile(filepath.Join(copyRoot, RootRecoverySourceJournalName), sourceRaw, 0o600); err != nil {
		root.Close()
		t.Fatal(err)
	}
	root.Close()
	before, err := snapshotPath(t, copyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
	}
	if result, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, plan.PlanSHA256); result.Generation.Path != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
	}
	after, err := snapshotPath(t, copyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if before.digest != after.digest {
		t.Fatal("rejected ambiguous journal rotation mutated the root")
	}
}

func TestRecoverOwnerScopeRootRejectsNonPreparedPendingJournal(t *testing.T) {
	copyRoot, plan, journal := prepareFileCopiedRecoveredRoot(t)
	journal.State = string(RootRecoveryStateFreshCommitted)
	journal.QuarantineSHA256 = journal.SourceSnapshotSHA256
	journal.QuarantineContentSHA256 = digestString("forged-pending-archive")
	root := openMigrationRoot(t, copyRoot)
	if err := persistRootRecoveryJournalNamed(root, RootRecoveryPendingJournalName, journal); err != nil {
		root.Close()
		t.Fatal(err)
	}
	root.Close()
	before, err := snapshotPath(t, copyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
	}
	if result, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, plan.PlanSHA256); result.Generation.Path != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
		t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
	}
	after, err := snapshotPath(t, copyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if before.digest != after.digest {
		t.Fatal("rejected non-prepared pending journal mutated the root")
	}
}

func TestInspectRotatedNestedRecoveryRejectsMissingOrTamperedSourceJournal(t *testing.T) {
	for _, mutation := range []string{"missing", "tampered"} {
		t.Run(mutation, func(t *testing.T) {
			copyRoot, plan, journal := prepareFileCopiedRecoveredRoot(t)
			root := openMigrationRoot(t, copyRoot)
			if err := persistRootRecoveryJournalNamed(root, RootRecoveryPendingJournalName, journal); err != nil {
				root.Close()
				t.Fatal(err)
			}
			root.Close()
			if err := os.Rename(filepath.Join(copyRoot, RootRecoveryJournalName), filepath.Join(copyRoot, RootRecoverySourceJournalName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(copyRoot, RootRecoveryPendingJournalName), filepath.Join(copyRoot, RootRecoveryJournalName)); err != nil {
				t.Fatal(err)
			}
			sourcePath := filepath.Join(copyRoot, RootRecoverySourceJournalName)
			if mutation == "missing" {
				if err := os.Remove(sourcePath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(sourcePath, []byte("tampered source recovery journal\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := snapshotPath(t, copyRoot)
			if err != nil {
				t.Fatal(err)
			}
			if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
				t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
			}
			if result, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, plan.PlanSHA256); result.Generation.Path != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
				t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
			}
			after, err := snapshotPath(t, copyRoot)
			if err != nil {
				t.Fatal(err)
			}
			if before.digest != after.digest {
				t.Fatal("rejected rotated source journal mutation changed the root")
			}
		})
	}
}

func TestInspectPendingNestedRecoveryRejectsSourceSnapshotTamper(t *testing.T) {
	for _, stage := range []string{"pending-written", "source-renamed"} {
		for _, target := range []string{"active", "migration", "archive"} {
			t.Run(stage+"/"+target, func(t *testing.T) {
				copyRoot, plan, journal := prepareFileCopiedRecoveredRoot(t)
				root := openMigrationRoot(t, copyRoot)
				if err := persistRootRecoveryJournalNamed(root, RootRecoveryPendingJournalName, journal); err != nil {
					root.Close()
					t.Fatal(err)
				}
				root.Close()
				if stage == "source-renamed" {
					if err := os.Rename(filepath.Join(copyRoot, RootRecoveryJournalName), filepath.Join(copyRoot, RootRecoverySourceJournalName)); err != nil {
						t.Fatal(err)
					}
				}
				recovery := mustReadSourceRecoveryJournal(t, copyRoot, stage)
				migration := mustReadMigrationJournal(t, copyRoot)
				switch target {
				case "active":
					if err := os.WriteFile(filepath.Join(copyRoot, generationsDirectory, migration.FreshGenerationID, "tampered-active-state"), []byte("tampered"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "migration":
					if err := os.Chmod(filepath.Join(copyRoot, MigrationJournalName), 0o400); err != nil {
						t.Fatal(err)
					}
				case "archive":
					if err := os.Chmod(filepath.Join(copyRoot, quarantineDirectory, recovery.QuarantineID, MigrationJournalName), 0o400); err != nil {
						t.Fatal(err)
					}
				}
				before, err := snapshotPath(t, copyRoot)
				if err != nil {
					t.Fatal(err)
				}
				if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
					t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
				}
				if result, err := RecoverOwnerScopeRoot(context.Background(), copyRoot, plan.PlanSHA256); result.Generation.Path != "" || !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
					t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
				}
				after, err := snapshotPath(t, copyRoot)
				if err != nil {
					t.Fatal(err)
				}
				if before.digest != after.digest {
					t.Fatal("rejected pending source snapshot mutation changed the root")
				}
			})
		}
	}
}

func mustReadSourceRecoveryJournal(t *testing.T, rootPath, stage string) rootRecoveryJournalV1 {
	t.Helper()
	name := RootRecoveryJournalName
	if stage == "source-renamed" {
		name = RootRecoverySourceJournalName
	}
	journal, err := decodeRootRecoveryJournal(mustReadFile(t, filepath.Join(rootPath, name)))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestInspectFileCopiedRecoveredRootRejectsArchiveAndRecoveryJournalTamper(t *testing.T) {
	copyRoot, _, _ := prepareFileCopiedRecoveredRoot(t)
	recovery := mustReadRecoveryJournal(t, copyRoot)
	archiveMigration := filepath.Join(copyRoot, quarantineDirectory, recovery.QuarantineID, MigrationJournalName)
	if err := os.Chmod(archiveMigration, 0o400); err != nil {
		t.Fatal(err)
	}
	archive := openMigrationRoot(t, filepath.Join(copyRoot, quarantineDirectory, recovery.QuarantineID))
	snapshot, err := snapshotDirectory(archive)
	archive.Close()
	if err != nil {
		t.Fatal(err)
	}
	recovery.QuarantineContentSHA256, err = digestSnapshotContent(snapshot.entries)
	if err != nil {
		t.Fatal(err)
	}
	root := openMigrationRoot(t, copyRoot)
	mustPersistRecoveryJournal(t, root, recovery)
	root.Close()
	if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeRecoveryNotEligible) {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
	}
}

func TestInspectFileCopiedRecoveredRootRejectsUnsafeArchiveNodes(t *testing.T) {
	for _, mutation := range []string{"group-writable", "symlink", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			copyRoot, _, _ := prepareFileCopiedRecoveredRoot(t)
			recovery := mustReadRecoveryJournal(t, copyRoot)
			archivePath := filepath.Join(copyRoot, quarantineDirectory, recovery.QuarantineID)
			source := filepath.Join(archivePath, MigrationJournalName)
			switch mutation {
			case "group-writable":
				if err := os.Chmod(source, 0o620); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(MigrationJournalName, filepath.Join(archivePath, "unsafe-link")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(source, filepath.Join(archivePath, "unsafe-hardlink")); err != nil {
					t.Fatal(err)
				}
			}
			if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeRecoveryNotEligible) {
				t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
			}
		})
	}
}

func TestInspectFileCopiedRecoveredRootRejectsContentAndLayoutTamper(t *testing.T) {
	rootPath, plan, _ := prepareRecoveryFixture(t)
	first, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}

	copyRoot := copyOwnerScopeRoot(t, rootPath)
	extraArchive := filepath.Join(copyRoot, quarantineDirectory, "quarantine_00000000000000000000000000000000")
	if err := os.Mkdir(extraArchive, 0o700); err != nil {
		t.Fatal(err)
	}
	if inspected, err := InspectOwnerScopeRootRecovery(copyRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeRecoveryNotEligible) {
		t.Fatalf("layout-tampered InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
	}

	movedRoot := moveOwnerScopeRootContents(t, rootPath)
	archiveJournal := filepath.Join(movedRoot, quarantineDirectory, first.Generation.Status.QuarantineID.String(), MigrationJournalName)
	if err := os.WriteFile(archiveJournal, []byte("tampered archive content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if inspected, err := InspectOwnerScopeRootRecovery(movedRoot); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeRecoveryNotEligible) {
		t.Fatalf("content-tampered InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
	}
}

func prepareFileCopiedRecoveredRoot(t *testing.T) (string, OwnerScopeRootRecoveryPlan, rootRecoveryJournalV1) {
	t.Helper()
	rootPath, initialPlan, _ := prepareRecoveryFixture(t)
	if _, err := RecoverOwnerScopeRoot(context.Background(), rootPath, initialPlan.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	copyRoot := copyOwnerScopeRoot(t, rootPath)
	root := openMigrationRoot(t, copyRoot)
	duplicate, identity, err := duplicateMigrationRoot(root)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	duplicate.Close()
	rawRecovery := mustReadFile(t, filepath.Join(copyRoot, RootRecoveryJournalName))
	recovery, err := decodeRootRecoveryJournal(rawRecovery)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	plan, wire, err := inspectCopiedRecoveredRootWithJournal(root, identity, recovery, rawRecovery)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	journal, err := newRootRecoveryJournal(identity, wire, plan.PlanSHA256)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	return copyRoot, plan, journal
}

func TestPrepareOwnerScopeGenerationResumesRecoveredRootRebindStages(t *testing.T) {
	for _, stage := range []string{"rebind-prepared", "standard-committed"} {
		t.Run(stage, func(t *testing.T) {
			movedRoot, identity, recovery, migration := prepareMovedRecoveredRoot(t)
			root := openMigrationRoot(t, movedRoot)
			recovery.State = string(RootRecoveryStateRebindPrepared)
			recovery.RebindRootIdentitySHA256 = identity
			mustPersistRecoveryJournal(t, root, recovery)
			if stage == "standard-committed" {
				migration.RootIdentitySHA256 = identity
				mustPersistMigrationJournal(t, root, migration)
			}
			root.Close()
			prepared, err := PrepareOwnerScopeGeneration(context.Background(), movedRoot)
			if err != nil || prepared.Path == "" {
				t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", prepared, err)
			}
			persistedRecovery := mustReadRecoveryJournal(t, movedRoot)
			persistedMigration := mustReadMigrationJournal(t, movedRoot)
			if persistedRecovery.State != string(RootRecoveryStateFreshCommitted) || persistedRecovery.RebindRootIdentitySHA256 != "" ||
				persistedRecovery.RootIdentitySHA256 != identity || persistedMigration.RootIdentitySHA256 != identity {
				t.Fatalf("resumed journals = %#v / %#v", persistedRecovery, persistedMigration)
			}
		})
	}
}

func TestPrepareOwnerScopeGenerationRejectsTamperedRecoveredRootRebind(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, string, *rootRecoveryJournalV1, *migrationJournalV1)
		want   error
	}{
		{name: "wrong rebind target", want: ErrOwnerScopeJournalCorrupt, mutate: func(_ *testing.T, _ string, _ string, recovery *rootRecoveryJournalV1, _ *migrationJournalV1) {
			recovery.State = string(RootRecoveryStateRebindPrepared)
			recovery.RebindRootIdentitySHA256 = digestString("wrong target")
		}},
		{name: "unexpected standard identity", want: ErrOwnerScopeJournalCorrupt, mutate: func(_ *testing.T, _ string, identity string, recovery *rootRecoveryJournalV1, migration *migrationJournalV1) {
			recovery.State = string(RootRecoveryStateRebindPrepared)
			recovery.RebindRootIdentitySHA256 = identity
			migration.RootIdentitySHA256 = digestString("unexpected standard identity")
		}},
		{name: "extra generation", want: ErrOwnerScopeSnapshotChanged, mutate: func(t *testing.T, root string, _ string, _ *rootRecoveryJournalV1, _ *migrationJournalV1) {
			if err := os.Mkdir(filepath.Join(root, generationsDirectory, "generation_00000000000000000000000000000000"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			movedRoot, identity, recovery, migration := prepareMovedRecoveredRoot(t)
			test.mutate(t, movedRoot, identity, &recovery, &migration)
			root := openMigrationRoot(t, movedRoot)
			mustPersistRecoveryJournal(t, root, recovery)
			mustPersistMigrationJournal(t, root, migration)
			root.Close()
			recoveryBefore := mustReadFile(t, filepath.Join(movedRoot, RootRecoveryJournalName))
			migrationBefore := mustReadFile(t, filepath.Join(movedRoot, MigrationJournalName))
			if generation, err := PrepareOwnerScopeGeneration(context.Background(), movedRoot); generation.Path != "" || !errors.Is(err, test.want) {
				t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
			}
			if !bytes.Equal(recoveryBefore, mustReadFile(t, filepath.Join(movedRoot, RootRecoveryJournalName))) ||
				!bytes.Equal(migrationBefore, mustReadFile(t, filepath.Join(movedRoot, MigrationJournalName))) {
				t.Fatal("rejected rebind tamper mutated journals")
			}
		})
	}
}

func TestOwnerScopeRootRecoveryJournalRejectsTamperingWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, []byte) []byte
	}{
		{name: "duplicate field", mutate: func(t *testing.T, raw []byte) []byte {
			t.Helper()
			return bytes.Replace(raw, []byte(`"schema_version":`), []byte(`"schema_version":"owner-scope-root-recovery-v1","schema_version":`), 1)
		}},
		{name: "unknown field", mutate: mutateRecoveryJournalField("unknown", true)},
		{name: "future schema", mutate: mutateRecoveryJournalField("schema_version", "owner-scope-root-recovery-v99")},
		{name: "source root identity", mutate: mutateRecoveryJournalField("source_root_identity_sha256", digestString("tampered source root"))},
		{name: "source journal digest", mutate: mutateRecoveryJournalField("source_journal_sha256", digestString("tampered journal"))},
		{name: "source snapshot digest", mutate: mutateRecoveryJournalField("source_snapshot_sha256", digestString("tampered snapshot"))},
		{name: "source entry count", mutate: mutateRecoveryJournalField("source_entry_count", 1)},
		{name: "source bytes", mutate: mutateRecoveryJournalField("source_bytes", 1)},
		{name: "retained quarantine", mutate: mutateRecoveryJournalFields(map[string]any{
			"has_retained_quarantine": true,
			"top_level_entries":       []string{currentGenerationFile, generationsDirectory, MigrationJournalName, quarantineDirectory},
		})},
		{name: "top level entries", mutate: mutateRecoveryJournalField("top_level_entries", []string{generationsDirectory, currentGenerationFile, MigrationJournalName})},
		{name: "recovery id", mutate: mutateRecoveryJournalField("recovery_id", "recovery_invalid")},
		{name: "root identity", mutate: mutateRecoveryJournalField("root_identity_sha256", digestString("tampered identity"))},
		{name: "quarantine id", mutate: mutateRecoveryJournalField("quarantine_id", "quarantine_invalid")},
		{name: "fresh migration id", mutate: mutateRecoveryJournalField("fresh_migration_id", "migration_invalid")},
		{name: "fresh generation id", mutate: mutateRecoveryJournalField("fresh_generation_id", "generation_invalid")},
		{name: "fresh generation digest", mutate: mutateRecoveryJournalField("fresh_generation_sha256", digestString("tampered generation"))},
		{name: "state", mutate: mutateRecoveryJournalField("state", "future_state")},
		{name: "plan digest", mutate: mutateRecoveryJournalField("plan_sha256", digestString("tampered plan"))},
		{name: "archive digest in prepared state", mutate: mutateRecoveryJournalField("quarantine_sha256", digestString("premature archive"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootPath, plan, _ := prepareRecoveryFixture(t)
			journalPath := filepath.Join(rootPath, RootRecoveryJournalName)
			raw := mustReadFile(t, journalPath)
			if err := os.WriteFile(journalPath, test.mutate(t, raw), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := snapshotPath(t, rootPath)
			if err != nil {
				t.Fatal(err)
			}
			if inspected, err := InspectOwnerScopeRootRecovery(rootPath); inspected.PlanSHA256 != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
				t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", inspected, err)
			}
			if result, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256); result.State != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
				t.Fatalf("RecoverOwnerScopeRoot() = %#v, %v", result, err)
			}
			after, err := snapshotPath(t, rootPath)
			if err != nil || after.digest != before.digest {
				t.Fatalf("tamper rejection changed root snapshot: %#v, %v", after, err)
			}
		})
	}
}

func mutateRecoveryJournalField(field string, value any) func(*testing.T, []byte) []byte {
	return mutateRecoveryJournalFields(map[string]any{field: value})
}

func mutateRecoveryJournalFields(fields map[string]any) func(*testing.T, []byte) []byte {
	return func(t *testing.T, raw []byte) []byte {
		t.Helper()
		var journal map[string]any
		if err := json.Unmarshal(raw, &journal); err != nil {
			t.Fatal(err)
		}
		for field, value := range fields {
			journal[field] = value
		}
		mutated, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		return append(mutated, '\n')
	}
}

func TestPrepareOwnerScopeGenerationResumesCommittedQuarantine(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	quarantined, err := migration.QuarantineUnownedLegacy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}

	generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if generation.Status.State != StateFreshCommitted || generation.Status.QuarantineID != quarantined.QuarantineID {
		t.Fatalf("resumed generation status = %#v, quarantined = %#v", generation.Status, quarantined)
	}
}

func TestPrepareOwnerScopeGenerationRejectsUnknownStateWithoutMutation(t *testing.T) {
	rootPath := t.TempDir()
	unknownPath := filepath.Join(rootPath, "unknown.dat")
	if err := os.WriteFile(unknownPath, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath); generation.Path != "" || !errors.Is(err, ErrOwnerScopeMigrationRequired) {
		t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
	}
	if raw, err := os.ReadFile(unknownPath); err != nil || string(raw) != "legacy" {
		t.Fatalf("unknown state changed = %q, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected root wrote a journal: %v", err)
	}
}

func TestOwnerScopeMigrationReturnsStableActiveGenerationPath(t *testing.T) {
	rootPath := t.TempDir()
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migration.ActiveGenerationPath(rootPath); !errors.Is(err, ErrOwnerScopeTransition) {
		t.Fatalf("ActiveGenerationPath() before commit error = %v", err)
	}
	committed, err := migration.CommitFreshGeneration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	activePath, err := migration.ActiveGenerationPath(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(rootPath, generationsDirectory, committed.FreshGenerationID)
	if activePath != wantPath {
		t.Fatalf("ActiveGenerationPath() = %q, want %q", activePath, wantPath)
	}
	if err := os.MkdirAll(filepath.Join(activePath, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activePath, "db", "registry.sqlite"), []byte("owned state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedRoot := openMigrationRoot(t, rootPath)
	reopened, err := OpenOwnerScopeMigration(reopenedRoot, OwnerScopeMigrationOptions{})
	reopenedRoot.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedPath, err := reopened.ActiveGenerationPath(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedPath != activePath {
		t.Fatalf("reopened ActiveGenerationPath() = %q, want %q", reopenedPath, activePath)
	}
	if raw, err := os.ReadFile(filepath.Join(reopenedPath, "db", "registry.sqlite")); err != nil || string(raw) != "owned state" {
		t.Fatalf("active generation state = %q, %v", raw, err)
	}
}

func TestOwnerScopeMigrationRejectsReplacementRootPath(t *testing.T) {
	rootPath := t.TempDir()
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	if _, err := migration.CommitFreshGeneration(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.ActiveGenerationPath(t.TempDir()); !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
		t.Fatalf("ActiveGenerationPath() replacement error = %v", err)
	}
}

func TestOpenOwnerScopeMigrationRejectsUnknownAndSymlinkRootsWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string)
	}{
		{name: "unknown", prepare: func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "unknown.dat"), []byte("legacy"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", prepare: func(t *testing.T, root string) {
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "db")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			test.prepare(t, rootPath)
			root := openMigrationRoot(t, rootPath)
			migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
			root.Close()
			if migration != nil || !errors.Is(err, ErrOwnerScopeMigrationRequired) {
				t.Fatalf("OpenOwnerScopeMigration() = %#v, %v", migration, err)
			}
			if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected root wrote a journal: %v", err)
			}
		})
	}
}

func TestOpenOwnerScopeMigrationRejectsResidualInternalStateAsNonEmpty(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, generationsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if migration != nil || !errors.Is(err, ErrOwnerScopeMigrationRequired) {
		t.Fatalf("OpenOwnerScopeMigration() = %#v, %v", migration, err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("residual internal state wrote a journal: %v", err)
	}
}

func TestCommitFreshGenerationRejectsFilesAddedAfterFreshPreparation(t *testing.T) {
	rootPath := t.TempDir()
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	if err := os.WriteFile(filepath.Join(rootPath, "late-legacy.sqlite"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.CommitFreshGeneration(context.Background()); !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
		t.Fatalf("CommitFreshGeneration() error = %v", err)
	}
	if status := migration.Status(); status.State != StateReconcileRequired {
		t.Fatalf("status after changed fresh root = %#v", status)
	}
}

func TestOpenOwnerScopeMigrationFencesMissingCommittedGenerationMarker(t *testing.T) {
	rootPath := t.TempDir()
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migration.CommitFreshGeneration(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(rootPath, currentGenerationFile)); err != nil {
		t.Fatal(err)
	}

	root = openMigrationRoot(t, rootPath)
	reopened, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if reopened != nil || !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
		t.Fatalf("OpenOwnerScopeMigration() = %#v, %v", reopened, err)
	}
	root = openMigrationRoot(t, rootPath)
	fenced, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer fenced.Close()
	if status := fenced.Status(); status.State != StateReconcileRequired {
		t.Fatalf("fenced status = %#v", status)
	}
}

func TestOwnerScopeMigrationQuarantinesExactLegacyInventoryAndReopens(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	status := migration.Status()
	if status.State != StatePrepared || status.InventoryID != RedevenLegacyInventoryV1 || status.InventorySHA256 == "" {
		t.Fatalf("prepared status = %#v", status)
	}
	quarantined, err := migration.QuarantineUnownedLegacy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.State != StateQuarantineCommitted || quarantined.QuarantineID.IsZero() {
		t.Fatalf("quarantined status = %#v", quarantined)
	}
	committed, err := migration.CommitFreshGeneration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if committed.State != StateFreshCommitted || committed.FreshGenerationID == "" {
		t.Fatalf("committed status = %#v", committed)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedRoot := openMigrationRoot(t, rootPath)
	reopened, err := OpenOwnerScopeMigration(reopenedRoot, OwnerScopeMigrationOptions{})
	reopenedRoot.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.Status(); got.State != StateFreshCommitted || got.QuarantineID != committed.QuarantineID || got.FreshGenerationID != committed.FreshGenerationID {
		t.Fatalf("reopened status = %#v", got)
	}
}

func TestOpenOwnerScopeMigrationSelectsEveryBuiltInHistoricalInventory(t *testing.T) {
	for _, inventory := range builtInOwnerScopeInventories {
		inventory := inventory
		t.Run(inventory.ID, func(t *testing.T) {
			rootPath := t.TempDir()
			writeLegacyInventory(t, rootPath, inventory.ID)
			root := openMigrationRoot(t, rootPath)
			migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
			root.Close()
			if err != nil {
				t.Fatal(err)
			}
			defer migration.Close()
			if status := migration.Status(); status.State != StatePrepared || status.InventoryID != inventory.ID || status.InventorySHA256 != inventory.SHA256 {
				t.Fatalf("prepared status = %#v", status)
			}
		})
	}
}

func TestPrepareOwnerScopeGenerationMigratesCompleteV065State(t *testing.T) {
	rootPath := t.TempDir()
	writeLegacyInventory(t, rootPath, RedevenV065InventoryV1)
	files := map[string]string{
		"db/closed_sessions.json":          `{"sessions":[]}`,
		"runtime-exec/runtime":             "runtime",
		"trust/trusted-time/checkpoint":    "checkpoint",
		"assets/packages/package.bin":      "package",
		"storage/objects/environment/data": "data",
	}
	for relative, contents := range files {
		path := filepath.Join(rootPath, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	generation, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if generation.Status.InventoryID != RedevenV065InventoryV1 || generation.Status.State != StateFreshCommitted || generation.Status.QuarantineID.IsZero() {
		t.Fatalf("prepared generation status = %#v", generation.Status)
	}
	quarantineRoot := filepath.Join(rootPath, quarantineDirectory, generation.Status.QuarantineID.String())
	for relative, contents := range files {
		path := filepath.Join(quarantineRoot, filepath.FromSlash(relative))
		if raw, err := os.ReadFile(path); err != nil || string(raw) != contents {
			t.Fatalf("quarantined %s = %q, %v", relative, raw, err)
		}
	}
	for _, root := range []string{"assets", "db", "runtime-exec", "storage", "trust"} {
		if _, err := os.Stat(filepath.Join(rootPath, root)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy root %s remains active: %v", root, err)
		}
		if info, err := os.Stat(filepath.Join(quarantineRoot, root)); err != nil || !info.IsDir() {
			t.Fatalf("quarantined root %s = %#v, %v", root, info, err)
		}
	}

	reopened, err := PrepareOwnerScopeGeneration(context.Background(), rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Path != generation.Path || reopened.Status.FreshGenerationID != generation.Status.FreshGenerationID {
		t.Fatalf("reopened generation = %#v, want %#v", reopened, generation)
	}
}

func TestOpenOwnerScopeMigrationAcceptsInterruptedV065Initialization(t *testing.T) {
	for _, test := range []struct {
		name       string
		databaseID string
	}{
		{name: "database-root-only"},
		{name: "single-database", databaseID: "db/registry.sqlite"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.Mkdir(filepath.Join(rootPath, "db"), 0o700); err != nil {
				t.Fatal(err)
			}
			if test.databaseID != "" {
				inventory := inventoryFixtureByID(t, RedevenV065InventoryV1)
				found := false
				for index := range inventory.SQLiteDatabases {
					if inventory.SQLiteDatabases[index].Path == test.databaseID {
						writeInventoryDatabase(t, rootPath, inventory.SQLiteDatabases[index])
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("database fixture %q not found", test.databaseID)
				}
			}
			root := openMigrationRoot(t, rootPath)
			migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
			root.Close()
			if err != nil {
				t.Fatal(err)
			}
			defer migration.Close()
			if status := migration.Status(); status.State != StatePrepared || status.InventoryID != RedevenV065InventoryV1 {
				t.Fatalf("prepared status = %#v", status)
			}
		})
	}
}

func TestOpenOwnerScopeMigrationRejectsUnknownInterruptedV065StateWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "unknown-database", path: "db/unknown.sqlite"},
		{name: "sqlite-sidecar-without-main", path: "db/registry.sqlite-wal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			path := filepath.Join(rootPath, filepath.FromSlash(test.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("unknown"), 0o600); err != nil {
				t.Fatal(err)
			}
			root := openMigrationRoot(t, rootPath)
			migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
			root.Close()
			if migration != nil || !errors.Is(err, ErrOwnerScopeMigrationRequired) {
				t.Fatalf("OpenOwnerScopeMigration() = %#v, %v", migration, err)
			}
			if raw, err := os.ReadFile(path); err != nil || string(raw) != "unknown" {
				t.Fatalf("rejected state changed = %q, %v", raw, err)
			}
			if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected root wrote a journal: %v", err)
			}
		})
	}
}

func TestOpenOwnerScopeMigrationRejectsCorruptOptionalV065DatabaseWithoutMutation(t *testing.T) {
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "db", "registry.sqlite")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if migration != nil || !errors.Is(err, ErrOwnerScopeInventoryCorrupt) {
		t.Fatalf("OpenOwnerScopeMigration() = %#v, %v", migration, err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "not sqlite" {
		t.Fatalf("corrupt database changed = %q, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt root wrote a journal: %v", err)
	}
}

func TestOpenOwnerScopeMigrationRejectsCorruptSQLiteInventoryWithoutMutation(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	if err := os.WriteFile(filepath.Join(rootPath, "db", "registry.sqlite"), []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if migration != nil || !errors.Is(err, ErrOwnerScopeInventoryCorrupt) {
		t.Fatalf("OpenOwnerScopeMigration() = %#v, %v", migration, err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, MigrationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt inventory wrote a journal: %v", err)
	}
}

func TestOwnerScopeMigrationRejectsSnapshotChangeBeforeQuarantine(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	if err := os.WriteFile(filepath.Join(rootPath, "db", "registry.sqlite"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.QuarantineUnownedLegacy(context.Background()); !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
		t.Fatalf("QuarantineUnownedLegacy() error = %v", err)
	}
	if got := migration.Status(); got.State != StateFailed {
		t.Fatalf("status after snapshot change = %#v", got)
	}
}

func TestCommitFreshGenerationRejectsChangedQuarantine(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	status, err := migration.QuarantineUnownedLegacy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(rootPath, quarantineDirectory, status.QuarantineID.String(), "assets", "package.bin")
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.CommitFreshGeneration(context.Background()); !errors.Is(err, ErrOwnerScopeSnapshotChanged) {
		t.Fatalf("CommitFreshGeneration() error = %v", err)
	}
	if status := migration.Status(); status.State != StateReconcileRequired {
		t.Fatalf("status after changed quarantine = %#v", status)
	}
}

func TestParseQuarantineIDIsSealedAndStrict(t *testing.T) {
	const value = "quarantine_0123456789abcdef0123456789abcdef"
	id, err := ParseQuarantineID(value)
	if err != nil || id.IsZero() || id.String() != value {
		t.Fatalf("ParseQuarantineID() = %#v, %v", id, err)
	}
	for _, invalid := range []string{"", "quarantine_short", "quarantine_0123456789ABCDEF0123456789ABCDEF", "other_0123456789abcdef0123456789abcdef"} {
		if id, err := ParseQuarantineID(invalid); err == nil || !id.IsZero() {
			t.Fatalf("ParseQuarantineID(%q) = %#v, %v", invalid, id, err)
		}
	}
}

func TestDeleteQuarantineRequiresCurrentContainmentEvidence(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migration.QuarantineUnownedLegacy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.CommitFreshGeneration(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.DeleteQuarantine(context.Background()); !errors.Is(err, ErrLegacyContainmentRequired) {
		t.Fatalf("DeleteQuarantine() error = %v", err)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}

	root = openMigrationRoot(t, rootPath)
	verified, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{Containment: acceptingContainmentVerifier{}})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	deleted, err := verified.DeleteQuarantine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if deleted.CleanupState != CleanupStateDeleted || deleted.State != StateFreshCommitted {
		t.Fatalf("deleted status = %#v", deleted)
	}
}

func TestOwnerScopeMigrationRejectsDuplicateJournalFields(t *testing.T) {
	rootPath := t.TempDir()
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(rootPath, MigrationJournalName)
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"state":"fresh_prepared"`), []byte(`"state":"fresh_prepared","state":"fresh_committed"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test did not tamper the journal")
	}
	if err := os.WriteFile(journalPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	root = openMigrationRoot(t, rootPath)
	reopened, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if reopened != nil || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
		t.Fatalf("duplicate journal OpenOwnerScopeMigration() = %#v, %v", reopened, err)
	}
}

func TestQuarantineCleanupJournalRejectsDuplicateAndUnsafeEntries(t *testing.T) {
	entry := snapshotEntry{
		Path: "db/registry.sqlite", Kind: "file", Device: 1, Inode: 2, UID: 1000,
		Mode: 0o600, Size: 5, Nlink: 1, SHA256: digestString("entry"),
	}
	validCleanup, migration := cleanupJournalFixture(t, entry)
	raw, err := json.Marshal(validCleanup)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(raw, []byte(`"state":"delete_prepared"`), []byte(`"state":"delete_prepared","state":"deleted"`), 1)
	if _, err := decodeCleanupJournal(duplicate, migration); err == nil {
		t.Fatal("cleanup decoder accepted a duplicate state field")
	}

	entry.Path = "db/../registry.sqlite"
	unsafeCleanup, unsafeMigration := cleanupJournalFixture(t, entry)
	unsafeRaw, err := json.Marshal(unsafeCleanup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCleanupJournal(unsafeRaw, unsafeMigration); err == nil {
		t.Fatal("cleanup decoder accepted path traversal")
	}
}

func cleanupJournalFixture(t *testing.T, entry snapshotEntry) (cleanupJournalV1, migrationJournalV1) {
	t.Helper()
	entries := []snapshotEntry{entry}
	rawEntries, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	migration := migrationJournalV1{
		MigrationID: "migration_0123456789abcdef0123456789abcdef", RootIdentitySHA256: digestString("root"),
		QuarantineID: "quarantine_0123456789abcdef0123456789abcdef", QuarantineSHA256: digestBytes(rawEntries), State: string(StateFreshCommitted),
	}
	cleanup := cleanupJournalV1{
		SchemaVersion: cleanupSchemaVersion, MigrationID: migration.MigrationID, RootIdentitySHA256: migration.RootIdentitySHA256,
		QuarantineID: migration.QuarantineID, QuarantineSHA256: migration.QuarantineSHA256, State: string(CleanupStateDeletePrepared), Entries: entries,
	}
	return cleanup, migration
}

func TestOwnerScopeMigrationResumesQuarantineWritingJournal(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	migration.mu.Lock()
	migration.journal.State = string(StateQuarantineWriting)
	migration.journal.QuarantineID = "quarantine_0123456789abcdef0123456789abcdef"
	if err := migration.persistJournal(); err != nil {
		migration.mu.Unlock()
		t.Fatal(err)
	}
	migration.mu.Unlock()
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}

	root = openMigrationRoot(t, rootPath)
	reopened, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	status, err := reopened.QuarantineUnownedLegacy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateQuarantineCommitted || status.QuarantineID.IsZero() {
		t.Fatalf("resumed status = %#v", status)
	}
}

func TestDeleteQuarantineResumesAfterPartialUnlink(t *testing.T) {
	rootPath := t.TempDir()
	writeRedevenLegacyInventory(t, rootPath)
	root := openMigrationRoot(t, rootPath)
	migration, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{Containment: acceptingContainmentVerifier{}})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migration.QuarantineUnownedLegacy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := migration.CommitFreshGeneration(context.Background()); err != nil {
		t.Fatal(err)
	}
	migration.mu.Lock()
	parent, err := openDirectoryAt(int(migration.root.Fd()), quarantineDirectory)
	if err != nil {
		migration.mu.Unlock()
		t.Fatal(err)
	}
	quarantine, err := openDirectoryAt(int(parent.Fd()), migration.journal.QuarantineID)
	if err != nil {
		parent.Close()
		migration.mu.Unlock()
		t.Fatal(err)
	}
	snapshot, err := snapshotDirectory(quarantine)
	quarantine.Close()
	parent.Close()
	if err != nil {
		migration.mu.Unlock()
		t.Fatal(err)
	}
	cleanup := cleanupJournalV1{
		SchemaVersion: cleanupSchemaVersion, MigrationID: migration.journal.MigrationID,
		RootIdentitySHA256: migration.journal.RootIdentitySHA256, QuarantineID: migration.journal.QuarantineID,
		QuarantineSHA256: migration.journal.QuarantineSHA256, State: string(CleanupStateDeleting), Entries: snapshot.entries,
	}
	if err := migration.persistCleanup(cleanup); err != nil {
		migration.mu.Unlock()
		t.Fatal(err)
	}
	migration.mu.Unlock()
	partial := filepath.Join(rootPath, quarantineDirectory, migration.Status().QuarantineID.String(), "assets", "package.bin")
	if err := os.Remove(partial); err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(); err != nil {
		t.Fatal(err)
	}

	root = openMigrationRoot(t, rootPath)
	reopened, err := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{Containment: acceptingContainmentVerifier{}})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	status, err := reopened.DeleteQuarantine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.CleanupState != CleanupStateDeleted {
		t.Fatalf("cleanup status = %#v", status)
	}
}

type acceptingContainmentVerifier struct{}

func (acceptingContainmentVerifier) VerifyLegacyContainment(_ context.Context, request LegacyContainmentRequest) (LegacyContainmentEvidence, error) {
	return NewLegacyContainmentEvidence(request), nil
}

func openMigrationRoot(t *testing.T, path string) *os.File {
	t.Helper()
	root, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertRelocationRejectedWithoutJournalMutation(t *testing.T, root string) {
	t.Helper()
	journalPath := filepath.Join(root, MigrationJournalName)
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if generation, err := PrepareOwnerScopeGeneration(context.Background(), root); generation.Path != "" || !errors.Is(err, ErrOwnerScopeJournalCorrupt) {
		t.Fatalf("PrepareOwnerScopeGeneration() = %#v, %v", generation, err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rejected relocation mutated its migration journal")
	}
}

func snapshotPath(t *testing.T, path string) (rootSnapshot, error) {
	t.Helper()
	root, err := os.Open(path)
	if err != nil {
		return rootSnapshot{}, err
	}
	defer root.Close()
	return snapshotDirectory(root)
}

func snapshotPathExcluding(t *testing.T, path string, exclusions map[string]struct{}) (rootSnapshot, error) {
	t.Helper()
	root, err := os.Open(path)
	if err != nil {
		return rootSnapshot{}, err
	}
	defer root.Close()
	return snapshotRoot(root, exclusions)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertRecoveryInspectionRejectedWithoutMutation(t *testing.T, root string, want error) {
	t.Helper()
	before, beforeErr := snapshotPath(t, root)
	journalBefore := mustReadFile(t, filepath.Join(root, MigrationJournalName))
	if plan, err := InspectOwnerScopeRootRecovery(root); plan.PlanSHA256 != "" || !errors.Is(err, want) {
		t.Fatalf("InspectOwnerScopeRootRecovery() = %#v, %v", plan, err)
	}
	journalAfter := mustReadFile(t, filepath.Join(root, MigrationJournalName))
	if !bytes.Equal(journalAfter, journalBefore) {
		t.Fatal("rejected recovery inspection mutated the migration journal")
	}
	if beforeErr == nil {
		after, err := snapshotPath(t, root)
		if err != nil || after.digest != before.digest {
			t.Fatalf("rejected recovery inspection changed root snapshot: %#v, %v", after, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, RootRecoveryJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected recovery inspection wrote a recovery journal: %v", err)
	}
}

func prepareRecoveryFixture(t *testing.T) (string, OwnerScopeRootRecoveryPlan, rootRecoveryJournalV1) {
	t.Helper()
	sourceRoot := t.TempDir()
	generation, err := PrepareOwnerScopeGeneration(context.Background(), sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(generation.Path, "db", "state")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootPath := copyOwnerScopeRoot(t, sourceRoot)
	plan, err := InspectOwnerScopeRootRecovery(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root := openMigrationRoot(t, rootPath)
	duplicate, identity, err := duplicateMigrationRoot(root)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	duplicate.Close()
	inspected, wire, err := inspectRecoveryCandidate(root, identity)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	if inspected.PlanSHA256 != plan.PlanSHA256 {
		root.Close()
		t.Fatalf("private recovery plan = %#v, public = %#v", inspected, plan)
	}
	journal, err := newRootRecoveryJournal(identity, wire, plan.PlanSHA256)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	mustPersistRecoveryJournal(t, root, journal)
	root.Close()
	return rootPath, plan, journal
}

func mustPersistRecoveryJournal(t *testing.T, root *os.File, journal rootRecoveryJournalV1) {
	t.Helper()
	if err := persistRootRecoveryJournal(root, journal); err != nil {
		t.Fatal(err)
	}
}

func mustPersistMigrationJournal(t *testing.T, root *os.File, journal migrationJournalV1) {
	t.Helper()
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicRootFile(root, MigrationJournalName, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustReadRecoveryJournal(t *testing.T, rootPath string) rootRecoveryJournalV1 {
	t.Helper()
	journal, err := decodeRootRecoveryJournal(mustReadFile(t, filepath.Join(rootPath, RootRecoveryJournalName)))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func mustReadMigrationJournal(t *testing.T, rootPath string) migrationJournalV1 {
	t.Helper()
	journal, err := decodeMigrationJournal(mustReadFile(t, filepath.Join(rootPath, MigrationJournalName)))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func prepareMovedRecoveredRoot(t *testing.T) (string, string, rootRecoveryJournalV1, migrationJournalV1) {
	t.Helper()
	rootPath, plan, _ := prepareRecoveryFixture(t)
	if _, err := RecoverOwnerScopeRoot(context.Background(), rootPath, plan.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	movedRoot := moveOwnerScopeRootContents(t, rootPath)
	root := openMigrationRoot(t, movedRoot)
	duplicate, identity, err := duplicateMigrationRoot(root)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	duplicate.Close()
	return movedRoot, identity, mustReadRecoveryJournal(t, movedRoot), mustReadMigrationJournal(t, movedRoot)
}

func prepareRecoveryWorkArchive(t *testing.T, root *os.File, journal rootRecoveryJournalV1) *os.File {
	t.Helper()
	if err := ensureDirectoryAt(int(root.Fd()), rootRecoveryWorkDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	work, err := openDirectoryAt(int(root.Fd()), rootRecoveryWorkDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectoryAt(int(work.Fd()), journal.QuarantineID, 0o700); err != nil {
		work.Close()
		t.Fatal(err)
	}
	archive, err := openDirectoryAt(int(work.Fd()), journal.QuarantineID)
	work.Close()
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

func prepareRecoveryFreshArtifacts(t *testing.T, root *os.File, journal rootRecoveryJournalV1) {
	t.Helper()
	if err := ensureDirectoryAt(int(root.Fd()), generationsDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	generations, err := openDirectoryAt(int(root.Fd()), generationsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectoryAt(int(generations.Fd()), journal.FreshGenerationID, 0o700); err != nil {
		generations.Close()
		t.Fatal(err)
	}
	generations.Close()
	if err := writeAtomicRootFile(root, currentGenerationFile, []byte(journal.FreshGenerationID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyOwnerScopeRoot(t *testing.T, source string) string {
	t.Helper()
	destination := t.TempDir()
	var copyDirectory func(string, string)
	copyDirectory = func(sourceDirectory, destinationDirectory string) {
		entries, err := os.ReadDir(sourceDirectory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			sourcePath := filepath.Join(sourceDirectory, entry.Name())
			destinationPath := filepath.Join(destinationDirectory, entry.Name())
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case info.IsDir():
				if err := os.Mkdir(destinationPath, info.Mode().Perm()); err != nil {
					t.Fatal(err)
				}
				copyDirectory(sourcePath, destinationPath)
			case info.Mode().IsRegular():
				raw, err := os.ReadFile(sourcePath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destinationPath, raw, info.Mode().Perm()); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unsupported owner-scope fixture entry %q", sourcePath)
			}
		}
	}
	copyDirectory(source, destination)
	return destination
}

func moveOwnerScopeRootContents(t *testing.T, source string) string {
	t.Helper()
	destination := t.TempDir()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.Rename(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}

func writeRedevenLegacyInventory(t *testing.T, root string) {
	t.Helper()
	writeLegacyInventory(t, root, RedevenLegacyInventoryV1)
}

func writeLegacyInventory(t *testing.T, root, inventoryID string) {
	t.Helper()
	for _, directory := range []string{"db", "assets", "storage"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	selected := inventoryFixtureByID(t, inventoryID)
	for _, databaseFixture := range selected.SQLiteDatabases {
		writeInventoryDatabase(t, root, databaseFixture)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "package.bin"), []byte("asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "storage", "namespace.bin"), []byte("storage"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func inventoryFixtureByID(t *testing.T, inventoryID string) *inventoryFixture {
	t.Helper()
	registry := readInventoryFixtureRegistry(t)
	for index := range registry.Inventories {
		if registry.Inventories[index].ID == inventoryID {
			return &registry.Inventories[index]
		}
	}
	t.Fatalf("inventory fixture %q not found", inventoryID)
	return nil
}

func writeInventoryDatabase(t *testing.T, root string, databaseFixture inventoryDatabaseFixture) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(databaseFixture.Path))
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, objectType := range []string{"table", "index"} {
		for _, object := range databaseFixture.SchemaObjects {
			if object.Type != objectType {
				continue
			}
			if _, err := database.Exec(object.SQL); err != nil {
				database.Close()
				t.Fatalf("create %s %s in %s: %v", object.Type, object.Name, databaseFixture.Path, err)
			}
		}
	}
	if _, err := database.Exec(fmt.Sprintf(`PRAGMA application_id = %d`, databaseFixture.ApplicationID)); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, databaseFixture.UserVersion)); err != nil {
		database.Close()
		t.Fatal(err)
	}
	for _, migration := range databaseFixture.MigrationVersions {
		for _, version := range migration.Versions {
			query := fmt.Sprintf(`INSERT INTO %q(version, applied_at) VALUES(?, 0)`, migration.Table)
			if _, err := database.Exec(query, version); err != nil {
				database.Close()
				t.Fatalf("seed %s migration version %d: %v", databaseFixture.Path, version, err)
			}
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

type inventoryFixtureRegistry struct {
	Inventories []inventoryFixture `json:"inventories"`
}

type inventoryFixture struct {
	ID              string                     `json:"id"`
	SQLiteDatabases []inventoryDatabaseFixture `json:"sqlite_databases"`
}

type inventoryDatabaseFixture struct {
	Path              string                      `json:"path"`
	ApplicationID     int64                       `json:"application_id"`
	UserVersion       int64                       `json:"user_version"`
	MigrationVersions []inventoryMigrationFixture `json:"migration_versions"`
	SchemaObjects     []sqliteSchemaObject        `json:"schema_objects"`
}

type inventoryMigrationFixture struct {
	Table    string  `json:"table"`
	Versions []int64 `json:"versions"`
}

func readInventoryFixtureRegistry(t *testing.T) inventoryFixtureRegistry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "plugin", "owner-scope-inventories-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry inventoryFixtureRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	return registry
}

func assertMigrationJournalExists(t *testing.T, root string) {
	t.Helper()
	if info, err := os.Stat(filepath.Join(root, MigrationJournalName)); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("migration journal stat = %#v, %v", info, err)
	}
}
