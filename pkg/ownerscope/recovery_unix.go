//go:build darwin || linux

package ownerscope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"golang.org/x/sys/unix"
)

const (
	rootRecoverySchemaVersion = "owner-scope-root-recovery-v1"
	rootRecoveryWorkDirectory = ".redevplugin-owner-scope-root-recovery-work"
	recoveredRootInventoryID  = "redevplugin-recovered-root-v1"
	recoveredRootStoreID      = "recovered-root"
)

var recoveredRootInventorySHA256 = digestString("redevplugin:owner-scope:recovered-root:v1")

type rootRecoveryPlanWireV1 struct {
	SchemaVersion         string   `json:"schema_version"`
	RootIdentitySHA256    string   `json:"root_identity_sha256"`
	SourceJournalSHA256   string   `json:"source_journal_sha256"`
	SourceSnapshotSHA256  string   `json:"source_snapshot_sha256"`
	SourceEntryCount      int      `json:"source_entry_count"`
	SourceBytes           int64    `json:"source_bytes"`
	HasRetainedQuarantine bool     `json:"has_retained_quarantine"`
	TopLevelEntries       []string `json:"top_level_entries"`
}

// InspectOwnerScopeRootRecovery performs a read-only admission check for the
// explicit copied-root recovery transaction.
func InspectOwnerScopeRootRecovery(rootPath string) (OwnerScopeRootRecoveryPlan, error) {
	root, identity, absoluteRoot, err := openLockedRecoveryRoot(rootPath)
	if err != nil {
		return OwnerScopeRootRecoveryPlan{}, err
	}
	defer closeLockedRecoveryRoot(root)
	_ = absoluteRoot
	if raw, readErr := readRootFile(root, RootRecoveryJournalName, 1<<20); readErr == nil {
		journal, decodeErr := decodeRootRecoveryJournal(raw)
		if decodeErr != nil {
			return OwnerScopeRootRecoveryPlan{}, ErrOwnerScopeJournalCorrupt
		}
		if journal.RootIdentitySHA256 != identity {
			if journal.State != string(RootRecoveryStateFreshCommitted) {
				return OwnerScopeRootRecoveryPlan{}, ErrOwnerScopeJournalCorrupt
			}
			return inspectRelocatedRecoveredRoot(root, identity, journal)
		}
		return recoveryPlanFromJournal(journal), nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return OwnerScopeRootRecoveryPlan{}, readErr
	}
	plan, _, err := inspectRecoveryCandidate(root, identity)
	return plan, err
}

// RecoverOwnerScopeRoot explicitly archives an inspected, untrusted copied
// root and commits a new empty generation. expectedPlanSHA256 must come from a
// matching InspectOwnerScopeRootRecovery result.
func RecoverOwnerScopeRoot(ctx context.Context, rootPath, expectedPlanSHA256 string) (OwnerScopeRootRecoveryResult, error) {
	if ctx == nil {
		return OwnerScopeRootRecoveryResult{}, ErrOwnerScopeTransition
	}
	root, identity, absoluteRoot, err := openLockedRecoveryRoot(rootPath)
	if err != nil {
		return OwnerScopeRootRecoveryResult{}, err
	}
	defer closeLockedRecoveryRoot(root)

	var journal rootRecoveryJournalV1
	var relocatedRecovery bool
	if raw, readErr := readRootFile(root, RootRecoveryJournalName, 1<<20); readErr == nil {
		journal, err = decodeRootRecoveryJournal(raw)
		if err != nil {
			return OwnerScopeRootRecoveryResult{}, ErrOwnerScopeJournalCorrupt
		}
		if journal.RootIdentitySHA256 != identity {
			if journal.State != string(RootRecoveryStateFreshCommitted) {
				return OwnerScopeRootRecoveryResult{}, ErrOwnerScopeJournalCorrupt
			}
			plan, migrationJournal, inspectErr := inspectRelocatedRecoveredRootWithJournal(root, identity, journal)
			if inspectErr != nil {
				return OwnerScopeRootRecoveryResult{}, inspectErr
			}
			if expectedPlanSHA256 == "" || expectedPlanSHA256 != plan.PlanSHA256 {
				return OwnerScopeRootRecoveryResult{}, ErrOwnerScopeRecoveryPlanMismatch
			}
			if err := ctx.Err(); err != nil {
				return OwnerScopeRootRecoveryResult{}, err
			}
			journal.SourceRootIdentitySHA256 = identity
			journal.PlanSHA256 = plan.PlanSHA256
			if err := persistRootRecoveryJournal(root, journal); err != nil {
				return OwnerScopeRootRecoveryResult{}, err
			}
			migration := &OwnerScopeMigration{root: root, journal: migrationJournal, recovery: journal}
			if err := migration.resumeRecoveryRootRebind(identity); err != nil {
				return recoveryErrorResult(absoluteRoot, migration.recovery), err
			}
			journal = migration.recovery
			relocatedRecovery = true
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return OwnerScopeRootRecoveryResult{}, readErr
	} else if !relocatedRecovery {
		plan, wire, inspectErr := inspectRecoveryCandidate(root, identity)
		if inspectErr != nil {
			return OwnerScopeRootRecoveryResult{}, inspectErr
		}
		if expectedPlanSHA256 == "" || expectedPlanSHA256 != plan.PlanSHA256 {
			return OwnerScopeRootRecoveryResult{}, ErrOwnerScopeRecoveryPlanMismatch
		}
		journal, err = newRootRecoveryJournal(identity, wire, plan.PlanSHA256)
		if err != nil {
			return OwnerScopeRootRecoveryResult{}, err
		}
		if err := persistRootRecoveryJournal(root, journal); err != nil {
			return OwnerScopeRootRecoveryResult{}, err
		}
	}
	if !relocatedRecovery && (expectedPlanSHA256 == "" || expectedPlanSHA256 != journal.PlanSHA256) {
		return OwnerScopeRootRecoveryResult{}, ErrOwnerScopeRecoveryPlanMismatch
	}
	if err := ctx.Err(); err != nil {
		return recoveryErrorResult(absoluteRoot, journal), err
	}
	if relocatedRecovery {
		if err := verifyFinalRecovery(root, journal); err != nil {
			return recoveryErrorResult(absoluteRoot, journal), err
		}
		if err := verifyRecoveryLexicalRoot(absoluteRoot, identity, journal); err != nil {
			return recoveryErrorResult(absoluteRoot, journal), err
		}
		return recoveryResult(absoluteRoot, journal), nil
	}

	if journal.State == string(RootRecoveryStatePrepared) {
		journal.State = string(RootRecoveryStateArchiveWriting)
		if err := persistRootRecoveryJournal(root, journal); err != nil {
			return recoveryErrorResult(absoluteRoot, journal), err
		}
	}
	if journal.State == string(RootRecoveryStateArchiveWriting) {
		if err := writeRecoveryArchive(root, &journal); err != nil {
			return recoveryErrorResult(absoluteRoot, journal), fmt.Errorf("archive owner scope recovery source: %w", err)
		}
	}
	if journal.State == string(RootRecoveryStateArchiveCommitted) {
		journal.State = string(RootRecoveryStateFreshPrepared)
		if err := persistRootRecoveryJournal(root, journal); err != nil {
			return recoveryErrorResult(absoluteRoot, journal), err
		}
	}
	if journal.State == string(RootRecoveryStateFreshPrepared) {
		if err := commitRecoveryFreshGeneration(root, &journal); err != nil {
			return recoveryErrorResult(absoluteRoot, journal), fmt.Errorf("commit owner scope recovery generation: %w", err)
		}
	}
	if journal.State != string(RootRecoveryStateFreshCommitted) {
		return recoveryErrorResult(absoluteRoot, journal), ErrOwnerScopeRecoveryRequired
	}
	if err := verifyFinalRecovery(root, journal); err != nil {
		return recoveryErrorResult(absoluteRoot, journal), fmt.Errorf("verify owner scope recovery result: %w", err)
	}
	if err := verifyRecoveryLexicalRoot(absoluteRoot, identity, journal); err != nil {
		return recoveryErrorResult(absoluteRoot, journal), fmt.Errorf("verify owner scope recovery path: %w", err)
	}
	return recoveryResult(absoluteRoot, journal), nil
}

var recoveryBeforePathReopenHook func()

func verifyRecoveryLexicalRoot(absoluteRoot, identity string, journal rootRecoveryJournalV1) error {
	if recoveryBeforePathReopenHook != nil {
		recoveryBeforePathReopenHook()
	}
	candidate, err := os.Open(absoluteRoot)
	if err != nil {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	root, reopenedIdentity, err := duplicateMigrationRoot(candidate)
	_ = candidate.Close()
	if err != nil {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	defer root.Close()
	if reopenedIdentity != identity {
		return ErrOwnerScopeSnapshotChanged
	}
	return verifyFinalRecovery(root, journal)
}

func openLockedRecoveryRoot(rootPath string) (*os.File, string, string, error) {
	absoluteRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, "", "", err
	}
	candidate, err := os.Open(absoluteRoot)
	if err != nil {
		return nil, "", "", err
	}
	root, identity, err := duplicateMigrationRoot(candidate)
	_ = candidate.Close()
	if err != nil {
		return nil, "", "", err
	}
	if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		root.Close()
		return nil, "", "", fmt.Errorf("lock owner scope recovery root: %w", err)
	}
	return root, identity, absoluteRoot, nil
}

func closeLockedRecoveryRoot(root *os.File) {
	if root == nil {
		return
	}
	_ = unix.Flock(int(root.Fd()), unix.LOCK_UN)
	_ = root.Close()
}

func inspectRecoveryCandidate(root *os.File, identity string) (OwnerScopeRootRecoveryPlan, rootRecoveryPlanWireV1, error) {
	if _, err := readRootFile(root, CleanupJournalName, 64<<20); err == nil {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, ErrOwnerScopeRecoveryNotEligible
	} else if !errors.Is(err, os.ErrNotExist) {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, err
	}
	raw, err := readRootFile(root, MigrationJournalName, 1<<20)
	if err != nil {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, errors.Join(ErrOwnerScopeRecoveryNotEligible, err)
	}
	journal, err := decodeMigrationJournal(raw)
	if err != nil || journal.State != string(StateFreshCommitted) || journal.RootIdentitySHA256 == identity {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, ErrOwnerScopeRecoveryNotEligible
	}
	if journal.FreshGenerationSHA256 != digestString("fresh:"+journal.FreshGenerationID) || !validRecoverySourceInventory(journal) {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, ErrOwnerScopeRecoveryNotEligible
	}
	migration := &OwnerScopeMigration{root: root, journal: journal}
	if err := migration.verifyActiveFreshGeneration(); err != nil {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, ErrOwnerScopeRecoveryNotEligible
	}
	if err := verifyRecoverySourceQuarantine(root, journal); err != nil {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, ErrOwnerScopeRecoveryNotEligible
	}
	snapshot, err := snapshotRoot(root, nil)
	if err != nil {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, errors.Join(ErrOwnerScopeRecoveryNotEligible, err)
	}
	topLevel := recoveryTopLevelEntries(snapshot.entries)
	wantTopLevel := []string{MigrationJournalName, currentGenerationFile, generationsDirectory}
	if journal.QuarantineID != "" {
		wantTopLevel = append(wantTopLevel, quarantineDirectory)
	}
	sort.Strings(wantTopLevel)
	if !slices.Equal(topLevel, wantTopLevel) {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, ErrOwnerScopeRecoveryNotEligible
	}
	var sourceBytes int64
	for _, entry := range snapshot.entries {
		if entry.Kind == "file" {
			sourceBytes += entry.Size
		}
	}
	wire := rootRecoveryPlanWireV1{
		SchemaVersion: rootRecoverySchemaVersion, RootIdentitySHA256: identity,
		SourceJournalSHA256: digestBytes(raw), SourceSnapshotSHA256: snapshot.digest,
		SourceEntryCount: len(snapshot.entries), SourceBytes: sourceBytes, HasRetainedQuarantine: journal.QuarantineID != "",
		TopLevelEntries: topLevel,
	}
	planSHA, err := digestCanonicalJSON(wire)
	if err != nil {
		return OwnerScopeRootRecoveryPlan{}, rootRecoveryPlanWireV1{}, err
	}
	return recoveryPlanFromWire(wire, planSHA), wire, nil
}

func inspectRelocatedRecoveredRoot(root *os.File, identity string, recovery rootRecoveryJournalV1) (OwnerScopeRootRecoveryPlan, error) {
	plan, _, err := inspectRelocatedRecoveredRootWithJournal(root, identity, recovery)
	return plan, err
}

func inspectRelocatedRecoveredRootWithJournal(root *os.File, identity string, recovery rootRecoveryJournalV1) (OwnerScopeRootRecoveryPlan, migrationJournalV1, error) {
	raw, err := readRootFile(root, MigrationJournalName, 1<<20)
	if err != nil {
		return OwnerScopeRootRecoveryPlan{}, migrationJournalV1{}, errors.Join(ErrOwnerScopeRecoveryNotEligible, err)
	}
	migration, err := decodeMigrationJournal(raw)
	if err != nil || migration.State != string(StateFreshCommitted) || !validRecoverySourceInventory(migration) || !recoveryMatchesMigration(recovery, migration) {
		return OwnerScopeRootRecoveryPlan{}, migrationJournalV1{}, ErrOwnerScopeRecoveryNotEligible
	}
	if err := verifyRecoveryRootEntries(root, true); err != nil {
		return OwnerScopeRootRecoveryPlan{}, migrationJournalV1{}, errors.Join(ErrOwnerScopeRecoveryNotEligible, err)
	}
	ownerMigration := &OwnerScopeMigration{root: root, journal: migration, recovery: recovery}
	if err := ownerMigration.verifyActiveFreshGeneration(); err != nil {
		return OwnerScopeRootRecoveryPlan{}, migrationJournalV1{}, errors.Join(ErrOwnerScopeRecoveryNotEligible, err)
	}
	if err := verifyRetainedRecoveryArchive(root, recovery); err != nil {
		return OwnerScopeRootRecoveryPlan{}, migrationJournalV1{}, errors.Join(ErrOwnerScopeRecoveryNotEligible, err)
	}
	wire := rootRecoveryPlanWireV1{
		SchemaVersion: rootRecoverySchemaVersion, RootIdentitySHA256: identity,
		SourceJournalSHA256: recovery.SourceJournalSHA256, SourceSnapshotSHA256: recovery.SourceSnapshotSHA256,
		SourceEntryCount: recovery.SourceEntryCount, SourceBytes: recovery.SourceBytes,
		HasRetainedQuarantine: recovery.HasRetainedQuarantine, TopLevelEntries: slices.Clone(recovery.TopLevelEntries),
	}
	planSHA, err := digestCanonicalJSON(wire)
	if err != nil {
		return OwnerScopeRootRecoveryPlan{}, migrationJournalV1{}, err
	}
	return recoveryPlanFromWire(wire, planSHA), migration, nil
}

func validRecoverySourceInventory(journal migrationJournalV1) bool {
	if journal.InventoryID == recoveredRootInventoryID {
		return journal.InventorySHA256 == recoveredRootInventorySHA256 && len(journal.Stores) == 1 &&
			journal.Stores[0] == (migrationStoreV1{ID: recoveredRootStoreID, Scope: "durable", Disposition: string(StoreDispositionQuarantine), Generation: journal.FreshGenerationID, Outcome: "quarantined"})
	}
	if journal.InventoryID == "" {
		return journal.InventorySHA256 == "" && len(journal.Stores) == 0 && journal.QuarantineID == ""
	}
	var inventory *builtInOwnerScopeInventory
	for index := range builtInOwnerScopeInventories {
		candidate := &builtInOwnerScopeInventories[index]
		if candidate.ID == journal.InventoryID && candidate.SHA256 == journal.InventorySHA256 {
			inventory = candidate
			break
		}
	}
	if inventory == nil || journal.QuarantineID == "" {
		return false
	}
	allowed := make(map[string]builtInOwnerScopeRootEntry, len(inventory.RootEntries))
	for _, entry := range inventory.RootEntries {
		allowed[entry.Path] = entry
	}
	seen := map[string]struct{}{}
	for _, store := range journal.Stores {
		entry, ok := allowed[store.ID]
		if !ok || entry.Scope != store.Scope || entry.Disposition != store.Disposition || store.Generation != journal.FreshGenerationID || store.Outcome != "quarantined" {
			return false
		}
		seen[store.ID] = struct{}{}
	}
	for _, entry := range inventory.RootEntries {
		if _, ok := seen[entry.Path]; entry.Required && !ok {
			return false
		}
	}
	return true
}

func verifyRecoverySourceQuarantine(root *os.File, journal migrationJournalV1) error {
	if journal.QuarantineID == "" {
		return nil
	}
	parent, err := openDirectoryAt(int(root.Fd()), quarantineDirectory)
	if err != nil {
		return err
	}
	defer parent.Close()
	entries, err := parent.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != journal.QuarantineID {
		return ErrOwnerScopeSnapshotChanged
	}
	quarantine, err := openDirectoryAt(int(parent.Fd()), journal.QuarantineID)
	if err != nil {
		return err
	}
	defer quarantine.Close()
	return validateOwnedGenerationDirectory(root, quarantine)
}

func recoveryTopLevelEntries(entries []snapshotEntry) []string {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		name := entry.Path
		for index, character := range name {
			if character == '/' {
				name = name[:index]
				break
			}
		}
		seen[name] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func newRootRecoveryJournal(identity string, wire rootRecoveryPlanWireV1, planSHA string) (rootRecoveryJournalV1, error) {
	recoveryID, err := newOpaqueID("recovery")
	if err != nil {
		return rootRecoveryJournalV1{}, err
	}
	quarantineID, err := newOpaqueID("quarantine")
	if err != nil {
		return rootRecoveryJournalV1{}, err
	}
	migrationID, err := newOpaqueID("migration")
	if err != nil {
		return rootRecoveryJournalV1{}, err
	}
	freshID, err := newOpaqueID("generation")
	if err != nil {
		return rootRecoveryJournalV1{}, err
	}
	return rootRecoveryJournalV1{
		SchemaVersion: rootRecoverySchemaVersion, RecoveryID: recoveryID, PlanSHA256: planSHA, RootIdentitySHA256: identity,
		SourceRootIdentitySHA256: wire.RootIdentitySHA256,
		SourceJournalSHA256:      wire.SourceJournalSHA256, SourceSnapshotSHA256: wire.SourceSnapshotSHA256,
		SourceEntryCount: wire.SourceEntryCount, SourceBytes: wire.SourceBytes, HasRetainedQuarantine: wire.HasRetainedQuarantine,
		TopLevelEntries: slices.Clone(wire.TopLevelEntries), State: string(RootRecoveryStatePrepared), QuarantineID: quarantineID,
		FreshMigrationID: migrationID, FreshGenerationID: freshID, FreshGenerationSHA256: digestString("fresh:" + freshID),
	}, nil
}

func writeRecoveryArchive(root *os.File, journal *rootRecoveryJournalV1) error {
	archive, final, err := openRecoveryArchive(root, *journal)
	if err != nil {
		return failRootRecovery(root, journal, err)
	}
	if archive == nil {
		if err := ensureDirectoryAt(int(root.Fd()), rootRecoveryWorkDirectory, 0o700); err != nil {
			return failRootRecovery(root, journal, err)
		}
		work, err := openDirectoryAt(int(root.Fd()), rootRecoveryWorkDirectory)
		if err != nil {
			return failRootRecovery(root, journal, err)
		}
		if err := ensureDirectoryAt(int(work.Fd()), journal.QuarantineID, 0o700); err != nil {
			work.Close()
			return failRootRecovery(root, journal, err)
		}
		archive, err = openDirectoryAt(int(work.Fd()), journal.QuarantineID)
		work.Close()
		if err != nil {
			return failRootRecovery(root, journal, err)
		}
	}
	defer archive.Close()
	if !final {
		for _, entry := range journal.TopLevelEntries {
			if err := moveStoreIntoQuarantine(int(root.Fd()), int(archive.Fd()), entry); err != nil {
				return failRootRecovery(root, journal, err)
			}
		}
		if err := unix.Fsync(int(archive.Fd())); err != nil {
			return failRootRecovery(root, journal, err)
		}
	}
	snapshot, err := snapshotDirectory(archive)
	if err != nil {
		return failRootRecovery(root, journal, errors.Join(ErrOwnerScopeSnapshotChanged, err))
	}
	if snapshot.digest != journal.SourceSnapshotSHA256 {
		return failRootRecovery(root, journal, fmt.Errorf("recovery archive digest mismatch: %w", ErrOwnerScopeSnapshotChanged))
	}
	if len(snapshot.entries) != journal.SourceEntryCount {
		return failRootRecovery(root, journal, fmt.Errorf("recovery archive entry count mismatch: %w", ErrOwnerScopeSnapshotChanged))
	}
	if !final {
		if err := archive.Close(); err != nil {
			return failRootRecovery(root, journal, err)
		}
		if err := unix.Renameat(int(root.Fd()), rootRecoveryWorkDirectory, int(root.Fd()), quarantineDirectory); err != nil {
			return failRootRecovery(root, journal, err)
		}
		if err := unix.Fsync(int(root.Fd())); err != nil {
			return failRootRecovery(root, journal, err)
		}
	}
	journal.QuarantineSHA256 = snapshot.digest
	journal.State = string(RootRecoveryStateArchiveCommitted)
	return persistRootRecoveryJournal(root, *journal)
}

func openRecoveryArchive(root *os.File, journal rootRecoveryJournalV1) (*os.File, bool, error) {
	workParent, workErr := openDirectoryAt(int(root.Fd()), rootRecoveryWorkDirectory)
	finalParent, finalErr := openDirectoryAt(int(root.Fd()), quarantineDirectory)
	if workErr == nil {
		if finalErr == nil {
			entries, err := finalParent.ReadDir(-1)
			if err != nil {
				finalParent.Close()
				workParent.Close()
				return nil, false, ErrOwnerScopeSnapshotChanged
			}
			finalParent.Close()
			if len(entries) == 1 && entries[0].Name() == journal.QuarantineID {
				workParent.Close()
				return nil, false, ErrOwnerScopeSnapshotChanged
			}
		} else if !errors.Is(finalErr, unix.ENOENT) {
			workParent.Close()
			return nil, false, finalErr
		}
		defer workParent.Close()
		archive, err := openDirectoryAt(int(workParent.Fd()), journal.QuarantineID)
		if errors.Is(err, unix.ENOENT) {
			entries, readErr := workParent.ReadDir(-1)
			if readErr != nil || len(entries) != 0 {
				return nil, false, ErrOwnerScopeSnapshotChanged
			}
			return nil, false, nil
		}
		return archive, false, err
	}
	if !errors.Is(workErr, unix.ENOENT) {
		return nil, false, workErr
	}
	if finalErr == nil {
		defer finalParent.Close()
		entries, err := finalParent.ReadDir(-1)
		if err != nil {
			return nil, false, ErrOwnerScopeSnapshotChanged
		}
		if len(entries) == 1 && entries[0].Name() == journal.QuarantineID {
			archive, err := openDirectoryAt(int(finalParent.Fd()), journal.QuarantineID)
			return archive, true, err
		}
		var source unix.Stat_t
		if slices.Contains(journal.TopLevelEntries, quarantineDirectory) && unix.Fstatat(int(root.Fd()), MigrationJournalName, &source, unix.AT_SYMLINK_NOFOLLOW) == nil {
			return nil, false, nil
		}
		return nil, false, ErrOwnerScopeSnapshotChanged
	}
	if !errors.Is(finalErr, unix.ENOENT) {
		return nil, false, finalErr
	}
	return nil, false, nil
}

func commitRecoveryFreshGeneration(root *os.File, journal *rootRecoveryJournalV1) error {
	archive, final, err := openRecoveryArchive(root, *journal)
	if err != nil || !final || archive == nil {
		if archive != nil {
			archive.Close()
		}
		return failRootRecovery(root, journal, errors.Join(ErrOwnerScopeSnapshotChanged, err))
	}
	snapshot, err := snapshotDirectory(archive)
	archive.Close()
	if err != nil || snapshot.digest != journal.QuarantineSHA256 {
		return failRootRecovery(root, journal, errors.Join(ErrOwnerScopeSnapshotChanged, err))
	}
	migrationJournal := recoveredMigrationJournal(*journal)
	raw, err := json.Marshal(migrationJournal)
	if err != nil {
		return failRootRecovery(root, journal, err)
	}
	markerExists, migrationExists, err := inspectOrCreateRecoveryFreshArtifacts(root, *journal, append(raw, '\n'))
	if err != nil {
		return failRootRecovery(root, journal, err)
	}
	if !markerExists {
		if err := writeAtomicRootFile(root, currentGenerationFile, []byte(journal.FreshGenerationID+"\n"), 0o600); err != nil {
			return failRootRecovery(root, journal, err)
		}
	}
	if !migrationExists {
		if err := writeAtomicRootFile(root, MigrationJournalName, append(raw, '\n'), 0o600); err != nil {
			return failRootRecovery(root, journal, err)
		}
	}
	if err := verifyRecoveryPrecommitRoot(root, *journal); err != nil {
		return failRootRecovery(root, journal, err)
	}
	journal.State = string(RootRecoveryStateFreshCommitted)
	if err := persistRootRecoveryJournal(root, *journal); err != nil {
		return err
	}
	return verifyFinalRecovery(root, *journal)
}

func inspectOrCreateRecoveryFreshArtifacts(root *os.File, journal rootRecoveryJournalV1, expectedMigration []byte) (bool, bool, error) {
	if err := verifyRecoveryRootEntries(root, false); err != nil {
		return false, false, err
	}
	markerExists := false
	if marker, err := readRootFile(root, currentGenerationFile, 1<<20); err == nil {
		if !bytes.Equal(marker, []byte(journal.FreshGenerationID+"\n")) {
			return false, false, ErrOwnerScopeSnapshotChanged
		}
		markerExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, false, err
	}

	migrationExists := false
	if raw, err := readRootFile(root, MigrationJournalName, 1<<20); err == nil {
		if !bytes.Equal(raw, expectedMigration) {
			return false, false, ErrOwnerScopeSnapshotChanged
		}
		migrationExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, false, err
	}
	if migrationExists && !markerExists {
		return false, false, ErrOwnerScopeSnapshotChanged
	}

	generations, err := openDirectoryAt(int(root.Fd()), generationsDirectory)
	if errors.Is(err, unix.ENOENT) {
		if markerExists || migrationExists {
			return false, false, ErrOwnerScopeSnapshotChanged
		}
		if err := ensureDirectoryAt(int(root.Fd()), generationsDirectory, 0o700); err != nil {
			return false, false, err
		}
		generations, err = openDirectoryAt(int(root.Fd()), generationsDirectory)
	}
	if err != nil {
		return false, false, err
	}
	defer generations.Close()
	entries, err := generations.ReadDir(-1)
	if err != nil {
		return false, false, err
	}
	if len(entries) == 0 {
		if markerExists || migrationExists {
			return false, false, ErrOwnerScopeSnapshotChanged
		}
		if err := ensureDirectoryAt(int(generations.Fd()), journal.FreshGenerationID, 0o700); err != nil {
			return false, false, err
		}
	} else if len(entries) != 1 || entries[0].Name() != journal.FreshGenerationID || !entries[0].IsDir() {
		return false, false, ErrOwnerScopeSnapshotChanged
	}
	active, err := openDirectoryAt(int(generations.Fd()), journal.FreshGenerationID)
	if err != nil {
		return false, false, err
	}
	defer active.Close()
	if err := validateOwnedGenerationDirectory(root, active); err != nil {
		return false, false, err
	}
	activeEntries, err := active.ReadDir(-1)
	if err != nil {
		return false, false, err
	}
	if len(activeEntries) != 0 {
		return false, false, ErrOwnerScopeSnapshotChanged
	}
	return markerExists, migrationExists, nil
}

func verifyRecoveryPrecommitRoot(root *os.File, recovery rootRecoveryJournalV1) error {
	if err := verifyRecoveryRootEntries(root, true); err != nil {
		return err
	}
	if err := verifyRetainedRecoveryArchive(root, recovery); err != nil {
		return err
	}
	migration := recoveredMigrationJournal(recovery)
	raw, err := json.Marshal(migration)
	if err != nil {
		return err
	}
	markerExists, migrationExists, err := inspectOrCreateRecoveryFreshArtifacts(root, recovery, append(raw, '\n'))
	if err != nil || !markerExists || !migrationExists {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	return nil
}

func verifyRecoveryRootEntries(root *os.File, exact bool) error {
	directory, err := openDirectoryAt(int(root.Fd()), ".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	allowed := map[string]struct{}{
		RootRecoveryJournalName: {},
		quarantineDirectory:     {},
		generationsDirectory:    {},
		currentGenerationFile:   {},
		MigrationJournalName:    {},
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok {
			return ErrOwnerScopeSnapshotChanged
		}
		seen[entry.Name()] = struct{}{}
	}
	if _, ok := seen[RootRecoveryJournalName]; !ok {
		return ErrOwnerScopeSnapshotChanged
	}
	if _, ok := seen[quarantineDirectory]; !ok {
		return ErrOwnerScopeSnapshotChanged
	}
	if exact && len(seen) != len(allowed) {
		return ErrOwnerScopeSnapshotChanged
	}
	return nil
}

func verifyRetainedRecoveryArchive(root *os.File, recovery rootRecoveryJournalV1) error {
	if recovery.QuarantineSHA256 == "" || recovery.QuarantineSHA256 != recovery.SourceSnapshotSHA256 {
		return ErrOwnerScopeSnapshotChanged
	}
	parent, err := openDirectoryAt(int(root.Fd()), quarantineDirectory)
	if err != nil {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	defer parent.Close()
	if err := validateOwnedGenerationDirectory(root, parent); err != nil {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	entries, err := parent.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != recovery.QuarantineID || !entries[0].IsDir() {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	archive, err := openDirectoryAt(int(parent.Fd()), recovery.QuarantineID)
	if err != nil {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	defer archive.Close()
	if err := validateOwnedGenerationDirectory(root, archive); err != nil {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	snapshot, err := snapshotDirectory(archive)
	if err != nil || snapshot.digest != recovery.QuarantineSHA256 || len(snapshot.entries) != recovery.SourceEntryCount {
		return errors.Join(ErrOwnerScopeSnapshotChanged, err)
	}
	return nil
}

func recoveredMigrationJournal(recovery rootRecoveryJournalV1) migrationJournalV1 {
	return migrationJournalV1{
		SchemaVersion: migrationSchemaVersion, MigrationID: recovery.FreshMigrationID, RootIdentitySHA256: recovery.RootIdentitySHA256,
		LegacySnapshotSHA256: recovery.SourceSnapshotSHA256, InventoryID: recoveredRootInventoryID,
		InventorySHA256: recoveredRootInventorySHA256, State: string(StateFreshCommitted), QuarantineID: recovery.QuarantineID,
		QuarantineSHA256: recovery.QuarantineSHA256, FreshGenerationID: recovery.FreshGenerationID,
		FreshGenerationSHA256: recovery.FreshGenerationSHA256,
		Stores:                []migrationStoreV1{{ID: recoveredRootStoreID, Scope: "durable", Disposition: string(StoreDispositionQuarantine), Generation: recovery.FreshGenerationID, Outcome: "quarantined"}},
	}
}

func verifyFinalRecovery(root *os.File, recovery rootRecoveryJournalV1) error {
	if recovery.State != string(RootRecoveryStateFreshCommitted) {
		return ErrOwnerScopeRecoveryRequired
	}
	if err := verifyRetainedRecoveryArchive(root, recovery); err != nil {
		return err
	}
	raw, err := readRootFile(root, MigrationJournalName, 1<<20)
	if err != nil {
		return ErrOwnerScopeJournalCorrupt
	}
	journal, err := decodeMigrationJournal(raw)
	if err != nil || !recoveryMatchesMigration(recovery, journal) {
		return ErrOwnerScopeJournalCorrupt
	}
	migration := &OwnerScopeMigration{root: root, journal: journal, recovery: recovery}
	return migration.verifyActiveFreshGeneration()
}

func recoveryMatchesMigration(recovery rootRecoveryJournalV1, journal migrationJournalV1) bool {
	want := recoveredMigrationJournal(recovery)
	return journal.SchemaVersion == want.SchemaVersion && journal.MigrationID == want.MigrationID &&
		journal.RootIdentitySHA256 == want.RootIdentitySHA256 && journal.LegacySnapshotSHA256 == want.LegacySnapshotSHA256 &&
		journal.InventoryID == want.InventoryID && journal.InventorySHA256 == want.InventorySHA256 && journal.State == want.State &&
		journal.QuarantineID == want.QuarantineID && journal.QuarantineSHA256 == want.QuarantineSHA256 &&
		journal.FreshGenerationID == want.FreshGenerationID && journal.FreshGenerationSHA256 == want.FreshGenerationSHA256 &&
		slices.Equal(journal.Stores, want.Stores)
}

func recoveryMigrationJournalsCompatible(recovery rootRecoveryJournalV1, journal migrationJournalV1, identity string) bool {
	if recovery.State == string(RootRecoveryStateFreshCommitted) {
		return recoveryMatchesMigration(recovery, journal)
	}
	if recovery.State != string(RootRecoveryStateRebindPrepared) || recovery.RebindRootIdentitySHA256 != identity {
		return false
	}
	current := recovery
	current.State = string(RootRecoveryStateFreshCommitted)
	current.RebindRootIdentitySHA256 = ""
	target := current
	target.RootIdentitySHA256 = identity
	return recoveryMatchesMigration(current, journal) || recoveryMatchesMigration(target, journal)
}

func persistRootRecoveryJournal(root *os.File, journal rootRecoveryJournalV1) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeAtomicRootFile(root, RootRecoveryJournalName, append(raw, '\n'), 0o600)
}

func failRootRecovery(root *os.File, journal *rootRecoveryJournalV1, cause error) error {
	if errors.Is(cause, ErrOwnerScopeSnapshotChanged) || errors.Is(cause, ErrOwnerScopeJournalCorrupt) {
		journal.State = string(RootRecoveryStateReconcileRequired)
		_ = persistRootRecoveryJournal(root, *journal)
	}
	return cause
}

func decodeRootRecoveryJournal(raw []byte) (rootRecoveryJournalV1, error) {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return rootRecoveryJournalV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal rootRecoveryJournalV1
	if err := decoder.Decode(&journal); err != nil {
		return rootRecoveryJournalV1{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rootRecoveryJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	if !validRootRecoveryJournal(journal) {
		return rootRecoveryJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	return journal, nil
}

func validRootRecoveryJournal(journal rootRecoveryJournalV1) bool {
	if journal.SchemaVersion != rootRecoverySchemaVersion || !validOpaqueID(journal.RecoveryID, "recovery") ||
		!validSHA256(journal.PlanSHA256) || !validSHA256(journal.SourceRootIdentitySHA256) ||
		!validSHA256(journal.RootIdentitySHA256) || !validSHA256(journal.SourceJournalSHA256) ||
		!validSHA256(journal.SourceSnapshotSHA256) || journal.SourceEntryCount < 1 || journal.SourceEntryCount > maxSnapshotEntries ||
		journal.SourceBytes < 1 || journal.SourceBytes > maxSnapshotBytes || !validOpaqueID(journal.QuarantineID, "quarantine") ||
		!validOpaqueID(journal.FreshMigrationID, "migration") || !validOpaqueID(journal.FreshGenerationID, "generation") ||
		journal.FreshGenerationSHA256 != digestString("fresh:"+journal.FreshGenerationID) || !validRootRecoveryState(RootRecoveryState(journal.State)) {
		return false
	}
	if !slices.Equal(journal.TopLevelEntries, sortedRecoveryTopLevel(journal.HasRetainedQuarantine)) {
		return false
	}
	wire := rootRecoveryPlanWireV1{
		SchemaVersion:         rootRecoverySchemaVersion,
		RootIdentitySHA256:    journal.SourceRootIdentitySHA256,
		SourceJournalSHA256:   journal.SourceJournalSHA256,
		SourceSnapshotSHA256:  journal.SourceSnapshotSHA256,
		SourceEntryCount:      journal.SourceEntryCount,
		SourceBytes:           journal.SourceBytes,
		HasRetainedQuarantine: journal.HasRetainedQuarantine,
		TopLevelEntries:       slices.Clone(journal.TopLevelEntries),
	}
	planSHA256, err := digestCanonicalJSON(wire)
	if err != nil || planSHA256 != journal.PlanSHA256 {
		return false
	}
	state := RootRecoveryState(journal.State)
	if state != RootRecoveryStateFreshCommitted && state != RootRecoveryStateRebindPrepared && journal.RootIdentitySHA256 != journal.SourceRootIdentitySHA256 {
		return false
	}
	if state == RootRecoveryStateRebindPrepared {
		return journal.QuarantineSHA256 == journal.SourceSnapshotSHA256 &&
			validSHA256(journal.RebindRootIdentitySHA256) && journal.RebindRootIdentitySHA256 != journal.RootIdentitySHA256
	}
	if journal.RebindRootIdentitySHA256 != "" {
		return false
	}
	if state == RootRecoveryStatePrepared || state == RootRecoveryStateArchiveWriting {
		return journal.QuarantineSHA256 == ""
	}
	if state == RootRecoveryStateReconcileRequired || state == RootRecoveryStateFailed {
		return journal.QuarantineSHA256 == "" || journal.QuarantineSHA256 == journal.SourceSnapshotSHA256
	}
	return journal.QuarantineSHA256 == journal.SourceSnapshotSHA256
}

func validRootRecoveryState(state RootRecoveryState) bool {
	switch state {
	case RootRecoveryStatePrepared, RootRecoveryStateArchiveWriting, RootRecoveryStateArchiveCommitted,
		RootRecoveryStateFreshPrepared, RootRecoveryStateFreshCommitted, RootRecoveryStateRebindPrepared,
		RootRecoveryStateReconcileRequired, RootRecoveryStateFailed:
		return true
	default:
		return false
	}
}

func sortedRecoveryTopLevel(hasQuarantine bool) []string {
	entries := []string{MigrationJournalName, currentGenerationFile, generationsDirectory}
	if hasQuarantine {
		entries = append(entries, quarantineDirectory)
	}
	sort.Strings(entries)
	return entries
}

func digestCanonicalJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}

func recoveryPlanFromWire(wire rootRecoveryPlanWireV1, planSHA string) OwnerScopeRootRecoveryPlan {
	return OwnerScopeRootRecoveryPlan{
		PlanSHA256: planSHA, RootIdentitySHA256: wire.RootIdentitySHA256,
		SourceJournalSHA256: wire.SourceJournalSHA256, SourceSnapshotSHA256: wire.SourceSnapshotSHA256,
		SourceEntryCount: wire.SourceEntryCount, SourceBytes: wire.SourceBytes, HasRetainedQuarantine: wire.HasRetainedQuarantine,
	}
}

func recoveryPlanFromJournal(journal rootRecoveryJournalV1) OwnerScopeRootRecoveryPlan {
	return OwnerScopeRootRecoveryPlan{
		PlanSHA256: journal.PlanSHA256, RootIdentitySHA256: journal.SourceRootIdentitySHA256,
		SourceJournalSHA256:  journal.SourceJournalSHA256,
		SourceSnapshotSHA256: journal.SourceSnapshotSHA256, SourceEntryCount: journal.SourceEntryCount,
		SourceBytes: journal.SourceBytes, HasRetainedQuarantine: journal.HasRetainedQuarantine,
	}
}

func recoveryResult(rootPath string, journal rootRecoveryJournalV1) OwnerScopeRootRecoveryResult {
	result := OwnerScopeRootRecoveryResult{Plan: recoveryPlanFromJournal(journal), State: RootRecoveryState(journal.State), RecoveryID: journal.RecoveryID}
	if journal.QuarantineID != "" {
		result.ArchivePath = filepath.Join(rootPath, quarantineDirectory, journal.QuarantineID)
	}
	if journal.State == string(RootRecoveryStateFreshCommitted) {
		result.Generation = OwnerScopeGeneration{
			Path:   filepath.Join(rootPath, generationsDirectory, journal.FreshGenerationID),
			Status: statusFromJournal(recoveredMigrationJournal(journal)),
		}
	}
	return result
}

func recoveryErrorResult(rootPath string, journal rootRecoveryJournalV1) OwnerScopeRootRecoveryResult {
	result := recoveryResult(rootPath, journal)
	result.Generation = OwnerScopeGeneration{}
	return result
}
