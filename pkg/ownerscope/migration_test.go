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
	registry := readInventoryFixtureRegistry(t)
	var selected *inventoryFixture
	for index := range registry.Inventories {
		if registry.Inventories[index].ID == inventoryID {
			selected = &registry.Inventories[index]
			break
		}
	}
	if selected == nil {
		t.Fatalf("inventory fixture %q not found", inventoryID)
	}
	for _, databaseFixture := range selected.SQLiteDatabases {
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
	if err := os.WriteFile(filepath.Join(root, "assets", "package.bin"), []byte("asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "storage", "namespace.bin"), []byte("storage"), 0o600); err != nil {
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
