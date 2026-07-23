//go:build darwin || linux

package ownerscope

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const (
	migrationSchemaVersion       = "owner-scope-migration-v1"
	cleanupSchemaVersion         = "quarantine-cleanup-v1"
	quarantineDirectory          = ".redevplugin-quarantine"
	generationsDirectory         = ".redevplugin-generations"
	currentGenerationFile        = ".redevplugin-current-generation"
	maxSnapshotEntries           = 200_000
	maxSnapshotBytes       int64 = 4 << 30
)

type migrationStoreV1 struct {
	ID          string `json:"id"`
	Scope       string `json:"scope"`
	Disposition string `json:"disposition"`
	Generation  string `json:"generation"`
	Outcome     string `json:"outcome"`
}

type migrationJournalV1 struct {
	SchemaVersion         string             `json:"schema_version"`
	MigrationID           string             `json:"migration_id"`
	RootIdentitySHA256    string             `json:"root_identity_sha256"`
	LegacySnapshotSHA256  string             `json:"legacy_snapshot_sha256"`
	InventoryID           string             `json:"inventory_id"`
	InventorySHA256       string             `json:"inventory_sha256"`
	State                 string             `json:"state"`
	QuarantineID          string             `json:"quarantine_id"`
	QuarantineSHA256      string             `json:"quarantine_sha256"`
	FreshGenerationID     string             `json:"fresh_generation_id"`
	FreshGenerationSHA256 string             `json:"fresh_generation_sha256"`
	Stores                []migrationStoreV1 `json:"stores"`
}

type cleanupJournalV1 struct {
	SchemaVersion      string          `json:"schema_version"`
	MigrationID        string          `json:"migration_id"`
	RootIdentitySHA256 string          `json:"root_identity_sha256"`
	QuarantineID       string          `json:"quarantine_id"`
	QuarantineSHA256   string          `json:"quarantine_sha256"`
	State              string          `json:"state"`
	Entries            []snapshotEntry `json:"entries"`
}

type snapshotEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	Nlink  uint64 `json:"nlink"`
	SHA256 string `json:"sha256"`
}

type rootSnapshot struct {
	entries []snapshotEntry
	digest  string
}

type sqliteSchemaObject struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	TableName string `json:"table_name"`
	SQL       string `json:"sql"`
}

func OpenOwnerScopeMigration(rootDir *os.File, options OwnerScopeMigrationOptions) (*OwnerScopeMigration, error) {
	root, identity, err := duplicateMigrationRoot(rootDir)
	if err != nil {
		return nil, err
	}
	closeRoot := true
	defer func() {
		if closeRoot {
			_ = root.Close()
		}
	}()
	if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock owner scope migration root: %w", err)
	}
	migration := &OwnerScopeMigration{root: root, options: options}
	if raw, readErr := readRootFile(root, MigrationJournalName, 1<<20); readErr == nil {
		journal, decodeErr := decodeMigrationJournal(raw)
		if decodeErr != nil || journal.RootIdentitySHA256 != identity {
			return nil, ErrOwnerScopeJournalCorrupt
		}
		migration.journal = journal
		migration.status = statusFromJournal(journal)
		if cleanupRaw, cleanupErr := readRootFile(root, CleanupJournalName, 64<<20); cleanupErr == nil {
			cleanup, decodeCleanupErr := decodeCleanupJournal(cleanupRaw, journal)
			if decodeCleanupErr != nil {
				return nil, ErrOwnerScopeJournalCorrupt
			}
			migration.status.CleanupState = CleanupState(cleanup.State)
			migration.cleanup = cleanup
		} else if !errors.Is(cleanupErr, os.ErrNotExist) {
			return nil, cleanupErr
		}
		if journal.State == string(StateFreshCommitted) {
			if verifyErr := migration.verifyActiveFreshGeneration(); verifyErr != nil {
				migration.journal.State = string(StateReconcileRequired)
				_ = migration.persistJournal()
				migration.status = statusFromJournal(migration.journal)
				return nil, verifyErr
			}
		}
		closeRoot = false
		return migration, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}

	snapshot, err := snapshotRoot(root, nil)
	if err != nil {
		return nil, errors.Join(ErrOwnerScopeMigrationRequired, err)
	}
	migrationID, err := newOpaqueID("migration")
	if err != nil {
		return nil, err
	}
	if len(snapshot.entries) == 0 {
		freshID, idErr := newOpaqueID("generation")
		if idErr != nil {
			return nil, idErr
		}
		migration.journal = migrationJournalV1{
			SchemaVersion:         migrationSchemaVersion,
			MigrationID:           migrationID,
			RootIdentitySHA256:    identity,
			LegacySnapshotSHA256:  snapshot.digest,
			State:                 string(StateFreshPrepared),
			FreshGenerationID:     freshID,
			FreshGenerationSHA256: digestString("fresh:" + freshID),
			Stores:                []migrationStoreV1{},
		}
		if err := migration.persistJournal(); err != nil {
			return nil, err
		}
		migration.status = statusFromJournal(migration.journal)
		closeRoot = false
		return migration, nil
	}

	inventoryID, inventoryDigest, stores, err := matchBuiltInInventory(root, snapshot)
	if err != nil {
		return nil, err
	}
	migration.journal = migrationJournalV1{
		SchemaVersion:        migrationSchemaVersion,
		MigrationID:          migrationID,
		RootIdentitySHA256:   identity,
		LegacySnapshotSHA256: snapshot.digest,
		InventoryID:          inventoryID,
		InventorySHA256:      inventoryDigest,
		State:                string(StatePrepared),
		Stores:               stores,
	}
	if err := migration.persistJournal(); err != nil {
		return nil, err
	}
	migration.status = statusFromJournal(migration.journal)
	closeRoot = false
	return migration, nil
}

func (migration *OwnerScopeMigration) QuarantineUnownedLegacy(ctx context.Context) (Status, error) {
	if migration == nil || ctx == nil {
		return Status{}, ErrOwnerScopeTransition
	}
	migration.mu.Lock()
	defer migration.mu.Unlock()
	if err := migration.ensureOpen(); err != nil {
		return cloneStatus(migration.status), err
	}
	if migration.journal.State == string(StateQuarantineCommitted) || migration.journal.State == string(StateFreshPrepared) || migration.journal.State == string(StateFreshCommitted) {
		return cloneStatus(migration.status), nil
	}
	if migration.journal.State != string(StatePrepared) && migration.journal.State != string(StateQuarantineWriting) {
		return cloneStatus(migration.status), ErrOwnerScopeTransition
	}
	if err := ctx.Err(); err != nil {
		return cloneStatus(migration.status), err
	}
	if migration.journal.State == string(StatePrepared) {
		snapshot, err := snapshotRoot(migration.root, preparedSnapshotExclusions())
		if err != nil || snapshot.digest != migration.journal.LegacySnapshotSHA256 {
			migration.journal.State = string(StateFailed)
			_ = migration.persistJournal()
			migration.status = statusFromJournal(migration.journal)
			return cloneStatus(migration.status), ErrOwnerScopeSnapshotChanged
		}
		quarantineID, err := newOpaqueID("quarantine")
		if err != nil {
			return cloneStatus(migration.status), err
		}
		migration.journal.QuarantineID = quarantineID
		migration.journal.State = string(StateQuarantineWriting)
		if err := migration.persistJournal(); err != nil {
			return cloneStatus(migration.status), err
		}
	}
	if err := ensureDirectoryAt(int(migration.root.Fd()), quarantineDirectory, 0o700); err != nil {
		return migration.failReconcile(err)
	}
	quarantineParent, err := openDirectoryAt(int(migration.root.Fd()), quarantineDirectory)
	if err != nil {
		return migration.failReconcile(err)
	}
	defer quarantineParent.Close()
	if err := ensureDirectoryAt(int(quarantineParent.Fd()), migration.journal.QuarantineID, 0o700); err != nil {
		return migration.failReconcile(err)
	}
	quarantine, err := openDirectoryAt(int(quarantineParent.Fd()), migration.journal.QuarantineID)
	if err != nil {
		return migration.failReconcile(err)
	}
	defer quarantine.Close()
	for index := range migration.journal.Stores {
		store := &migration.journal.Stores[index]
		if err := moveStoreIntoQuarantine(int(migration.root.Fd()), int(quarantine.Fd()), store.ID); err != nil {
			return migration.failReconcile(err)
		}
		store.Outcome = "quarantined"
	}
	if err := unix.Fsync(int(quarantine.Fd())); err != nil {
		return migration.failReconcile(err)
	}
	if err := unix.Fsync(int(migration.root.Fd())); err != nil {
		return migration.failReconcile(err)
	}
	quarantineSnapshot, err := snapshotDirectory(quarantine)
	if err != nil {
		return migration.failReconcile(err)
	}
	if quarantineSnapshot.digest != migration.journal.LegacySnapshotSHA256 {
		return migration.failReconcile(ErrOwnerScopeSnapshotChanged)
	}
	migration.journal.QuarantineSHA256 = quarantineSnapshot.digest
	migration.journal.State = string(StateQuarantineCommitted)
	if err := migration.persistJournal(); err != nil {
		return migration.failReconcile(err)
	}
	migration.status = statusFromJournal(migration.journal)
	return cloneStatus(migration.status), nil
}

func (migration *OwnerScopeMigration) CommitFreshGeneration(ctx context.Context) (Status, error) {
	if migration == nil || ctx == nil {
		return Status{}, ErrOwnerScopeTransition
	}
	migration.mu.Lock()
	defer migration.mu.Unlock()
	if err := migration.ensureOpen(); err != nil {
		return cloneStatus(migration.status), err
	}
	if migration.journal.State == string(StateFreshCommitted) {
		return cloneStatus(migration.status), nil
	}
	if migration.journal.State == string(StateQuarantineCommitted) {
		freshID, err := newOpaqueID("generation")
		if err != nil {
			return cloneStatus(migration.status), err
		}
		migration.journal.FreshGenerationID = freshID
		migration.journal.FreshGenerationSHA256 = digestString("fresh:" + freshID)
		migration.journal.State = string(StateFreshPrepared)
		if err := migration.persistJournal(); err != nil {
			return cloneStatus(migration.status), err
		}
	}
	if migration.journal.State != string(StateFreshPrepared) || migration.journal.FreshGenerationID == "" {
		return cloneStatus(migration.status), ErrOwnerScopeTransition
	}
	if err := ctx.Err(); err != nil {
		return cloneStatus(migration.status), err
	}
	if err := migration.verifyFreshPreparation(); err != nil {
		return migration.failReconcile(err)
	}
	if err := ensureDirectoryAt(int(migration.root.Fd()), generationsDirectory, 0o700); err != nil {
		return migration.failReconcile(err)
	}
	generations, err := openDirectoryAt(int(migration.root.Fd()), generationsDirectory)
	if err != nil {
		return migration.failReconcile(err)
	}
	defer generations.Close()
	if err := ensureDirectoryAt(int(generations.Fd()), migration.journal.FreshGenerationID, 0o700); err != nil {
		return migration.failReconcile(err)
	}
	if err := writeAtomicRootFile(migration.root, currentGenerationFile, []byte(migration.journal.FreshGenerationID+"\n"), 0o600); err != nil {
		return migration.failReconcile(err)
	}
	for index := range migration.journal.Stores {
		migration.journal.Stores[index].Generation = migration.journal.FreshGenerationID
		if migration.journal.Stores[index].Outcome == "" {
			migration.journal.Stores[index].Outcome = "fresh"
		}
	}
	migration.journal.State = string(StateFreshCommitted)
	if err := migration.persistJournal(); err != nil {
		return migration.failReconcile(err)
	}
	migration.status = statusFromJournal(migration.journal)
	return cloneStatus(migration.status), nil
}

// ActiveGenerationPath returns the durable state root for the committed
// owner-scoped generation. The supplied path must still identify the exact
// migration root that was opened, so callers cannot redirect state through a
// replacement directory between migration and host initialization.
func (migration *OwnerScopeMigration) ActiveGenerationPath(rootPath string) (string, error) {
	if migration == nil {
		return "", ErrOwnerScopeTransition
	}
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" {
		return "", ErrOwnerScopeMigrationRequired
	}
	absoluteRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return "", err
	}

	migration.mu.Lock()
	defer migration.mu.Unlock()
	if err := migration.ensureOpen(); err != nil {
		return "", err
	}
	if migration.journal.State != string(StateFreshCommitted) || !validOpaqueID(migration.journal.FreshGenerationID, "generation") {
		return "", ErrOwnerScopeTransition
	}

	candidate, err := os.Open(absoluteRoot)
	if err != nil {
		return "", err
	}
	verified, identity, err := duplicateMigrationRoot(candidate)
	_ = candidate.Close()
	if err != nil {
		return "", err
	}
	_ = verified.Close()
	if identity != migration.journal.RootIdentitySHA256 {
		return "", ErrOwnerScopeSnapshotChanged
	}
	if err := migration.verifyActiveFreshGeneration(); err != nil {
		return "", err
	}
	return filepath.Join(absoluteRoot, generationsDirectory, migration.journal.FreshGenerationID), nil
}

func (migration *OwnerScopeMigration) DeleteQuarantine(ctx context.Context) (Status, error) {
	if migration == nil || ctx == nil {
		return Status{}, ErrOwnerScopeTransition
	}
	migration.mu.Lock()
	defer migration.mu.Unlock()
	if err := migration.ensureOpen(); err != nil {
		return cloneStatus(migration.status), err
	}
	if migration.journal.State != string(StateFreshCommitted) || migration.journal.QuarantineID == "" {
		return cloneStatus(migration.status), ErrOwnerScopeTransition
	}
	if migration.status.CleanupState == CleanupStateDeleted {
		return cloneStatus(migration.status), nil
	}
	if migration.options.Containment == nil {
		return cloneStatus(migration.status), ErrLegacyContainmentRequired
	}
	request := LegacyContainmentRequest{
		migrationID: migration.journal.MigrationID, rootIdentitySHA256: migration.journal.RootIdentitySHA256,
		quarantineID: quarantineIDFromWire(migration.journal.QuarantineID), quarantineSHA256: migration.journal.QuarantineSHA256,
	}
	evidence, err := migration.options.Containment.VerifyLegacyContainment(ctx, request)
	if err != nil || evidence.request != request {
		return cloneStatus(migration.status), errors.Join(ErrLegacyContainmentRequired, err)
	}
	cleanup := migration.cleanup
	parent, err := openDirectoryAt(int(migration.root.Fd()), quarantineDirectory)
	if err != nil {
		return migration.cleanupReconcile(cleanup, err)
	}
	defer parent.Close()
	quarantine, err := openDirectoryAt(int(parent.Fd()), request.quarantineID.String())
	if err != nil {
		if errors.Is(err, unix.ENOENT) && cleanup.State != "" {
			cleanup.State = string(CleanupStateDeleted)
			if persistErr := migration.persistCleanup(cleanup); persistErr != nil {
				return migration.cleanupReconcile(cleanup, persistErr)
			}
			return cloneStatus(migration.status), nil
		}
		return migration.cleanupReconcile(cleanup, err)
	}
	snapshot, err := snapshotDirectory(quarantine)
	if err != nil {
		quarantine.Close()
		return migration.cleanupReconcile(cleanup, err)
	}
	if cleanup.State == "" {
		if snapshot.digest != request.quarantineSHA256 {
			quarantine.Close()
			return migration.cleanupReconcile(cleanup, ErrOwnerScopeSnapshotChanged)
		}
		cleanup = cleanupJournalV1{
			SchemaVersion: cleanupSchemaVersion, MigrationID: request.migrationID, RootIdentitySHA256: request.rootIdentitySHA256,
			QuarantineID: request.quarantineID.String(), QuarantineSHA256: request.quarantineSHA256, State: string(CleanupStateDeletePrepared),
			Entries: append([]snapshotEntry(nil), snapshot.entries...),
		}
		if err := migration.persistCleanup(cleanup); err != nil {
			quarantine.Close()
			return cloneStatus(migration.status), err
		}
		cleanup.State = string(CleanupStateDeleting)
		if err := migration.persistCleanup(cleanup); err != nil {
			quarantine.Close()
			return cloneStatus(migration.status), err
		}
	} else if !snapshotIsExactSubset(snapshot.entries, cleanup.Entries) {
		quarantine.Close()
		return migration.cleanupReconcile(cleanup, ErrOwnerScopeSnapshotChanged)
	}
	expectedEntries := make(map[string]snapshotEntry, len(cleanup.Entries))
	for _, entry := range cleanup.Entries {
		expectedEntries[entry.Path] = entry
	}
	if err := deleteDirectoryContents(int(quarantine.Fd()), "", expectedEntries); err != nil {
		quarantine.Close()
		return migration.cleanupReconcile(cleanup, err)
	}
	if err := quarantine.Close(); err != nil {
		return migration.cleanupReconcile(cleanup, err)
	}
	if err := unix.Unlinkat(int(parent.Fd()), request.quarantineID.String(), unix.AT_REMOVEDIR); err != nil {
		return migration.cleanupReconcile(cleanup, err)
	}
	if err := unix.Fsync(int(parent.Fd())); err != nil {
		return migration.cleanupReconcile(cleanup, err)
	}
	cleanup.State = string(CleanupStateDeleted)
	if err := migration.persistCleanup(cleanup); err != nil {
		return migration.cleanupReconcile(cleanup, err)
	}
	migration.status.CleanupState = CleanupStateDeleted
	return cloneStatus(migration.status), nil
}

func (migration *OwnerScopeMigration) Close() error {
	if migration == nil {
		return nil
	}
	migration.mu.Lock()
	defer migration.mu.Unlock()
	if migration.closed {
		return nil
	}
	migration.closed = true
	if migration.root == nil {
		return nil
	}
	_ = unix.Flock(int(migration.root.Fd()), unix.LOCK_UN)
	err := migration.root.Close()
	migration.root = nil
	return err
}

func (migration *OwnerScopeMigration) ensureOpen() error {
	if migration.closed || migration.root == nil {
		return ErrOwnerScopeTransition
	}
	return nil
}

func (migration *OwnerScopeMigration) persistJournal() error {
	raw, err := json.Marshal(migration.journal)
	if err != nil {
		return err
	}
	return writeAtomicRootFile(migration.root, MigrationJournalName, append(raw, '\n'), 0o600)
}

func (migration *OwnerScopeMigration) persistCleanup(cleanup cleanupJournalV1) error {
	raw, err := json.Marshal(cleanup)
	if err != nil {
		return err
	}
	if err := writeAtomicRootFile(migration.root, CleanupJournalName, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	migration.status.CleanupState = CleanupState(cleanup.State)
	migration.cleanup = cleanup
	return nil
}

func (migration *OwnerScopeMigration) failReconcile(cause error) (Status, error) {
	migration.journal.State = string(StateReconcileRequired)
	_ = migration.persistJournal()
	migration.status = statusFromJournal(migration.journal)
	return cloneStatus(migration.status), cause
}

func (migration *OwnerScopeMigration) cleanupReconcile(cleanup cleanupJournalV1, cause error) (Status, error) {
	cleanup.State = string(CleanupStateReconcileRequired)
	_ = migration.persistCleanup(cleanup)
	return cloneStatus(migration.status), cause
}

func (migration *OwnerScopeMigration) verifyFreshPreparation() error {
	exclusions := map[string]struct{}{MigrationJournalName: {}}
	if migration.journal.InventoryID != "" {
		parent, err := openDirectoryAt(int(migration.root.Fd()), quarantineDirectory)
		if err != nil {
			return err
		}
		quarantine, err := openDirectoryAt(int(parent.Fd()), migration.journal.QuarantineID)
		_ = parent.Close()
		if err != nil {
			return err
		}
		quarantineSnapshot, snapshotErr := snapshotDirectory(quarantine)
		_ = quarantine.Close()
		if snapshotErr != nil {
			return snapshotErr
		}
		if quarantineSnapshot.digest != migration.journal.QuarantineSHA256 {
			return ErrOwnerScopeSnapshotChanged
		}
		exclusions[quarantineDirectory] = struct{}{}
	}
	snapshot, err := snapshotRoot(migration.root, exclusions)
	if err != nil {
		return err
	}
	return validateFreshArtifacts(snapshot, migration.journal.FreshGenerationID, false)
}

func (migration *OwnerScopeMigration) verifyActiveFreshGeneration() error {
	exclusions := map[string]struct{}{MigrationJournalName: {}}
	if migration.cleanup.State != "" {
		exclusions[CleanupJournalName] = struct{}{}
	}
	if migration.journal.QuarantineID != "" {
		parent, err := openDirectoryAt(int(migration.root.Fd()), quarantineDirectory)
		if err != nil {
			return err
		}
		if migration.cleanup.State == string(CleanupStateDeleted) {
			parentSnapshot, snapshotErr := snapshotDirectory(parent)
			_ = parent.Close()
			if snapshotErr != nil {
				return snapshotErr
			}
			if len(parentSnapshot.entries) != 0 {
				return ErrOwnerScopeSnapshotChanged
			}
		} else {
			_ = parent.Close()
		}
		exclusions[quarantineDirectory] = struct{}{}
	}
	exclusions[generationsDirectory] = struct{}{}
	snapshot, err := snapshotRoot(migration.root, exclusions)
	if err != nil {
		return err
	}
	if len(snapshot.entries) != 1 || snapshot.entries[0].Path != currentGenerationFile ||
		snapshot.entries[0].Kind != "file" ||
		snapshot.entries[0].SHA256 != digestBytes([]byte(migration.journal.FreshGenerationID+"\n")) {
		return ErrOwnerScopeSnapshotChanged
	}

	generations, err := openDirectoryAt(int(migration.root.Fd()), generationsDirectory)
	if err != nil {
		return err
	}
	defer generations.Close()
	if err := validateOwnedGenerationDirectory(migration.root, generations); err != nil {
		return err
	}
	entries, err := generations.ReadDir(-1)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != migration.journal.FreshGenerationID {
		return ErrOwnerScopeSnapshotChanged
	}
	active, err := openDirectoryAt(int(generations.Fd()), migration.journal.FreshGenerationID)
	if err != nil {
		return err
	}
	defer active.Close()
	return validateOwnedGenerationDirectory(migration.root, active)
}

func validateOwnedGenerationDirectory(root, directory *os.File) error {
	var rootStat, directoryStat unix.Stat_t
	if err := unix.Fstat(int(root.Fd()), &rootStat); err != nil {
		return err
	}
	if err := unix.Fstat(int(directory.Fd()), &directoryStat); err != nil {
		return err
	}
	mode := uint32(directoryStat.Mode)
	if mode&unix.S_IFMT != unix.S_IFDIR || mode&0o022 != 0 || directoryStat.Dev != rootStat.Dev || directoryStat.Uid != rootStat.Uid {
		return ErrOwnerScopeSnapshotChanged
	}
	return nil
}

func validateFreshArtifacts(snapshot rootSnapshot, freshGenerationID string, required bool) error {
	seenGenerations := false
	seenGeneration := false
	seenCurrent := false
	for _, entry := range snapshot.entries {
		switch entry.Path {
		case generationsDirectory:
			seenGenerations = entry.Kind == "directory"
			if !seenGenerations {
				return ErrOwnerScopeSnapshotChanged
			}
		case generationsDirectory + "/" + freshGenerationID:
			seenGeneration = entry.Kind == "directory"
			if !seenGeneration {
				return ErrOwnerScopeSnapshotChanged
			}
		case currentGenerationFile:
			seenCurrent = entry.Kind == "file" && entry.SHA256 == digestBytes([]byte(freshGenerationID+"\n"))
			if !seenCurrent {
				return ErrOwnerScopeSnapshotChanged
			}
		default:
			return ErrOwnerScopeSnapshotChanged
		}
	}
	if seenGeneration && !seenGenerations || seenCurrent && !seenGeneration {
		return ErrOwnerScopeSnapshotChanged
	}
	if required && (!seenGenerations || !seenGeneration || !seenCurrent) {
		return ErrOwnerScopeSnapshotChanged
	}
	return nil
}

func duplicateMigrationRoot(root *os.File) (*os.File, string, error) {
	if root == nil {
		return nil, "", ErrOwnerScopeMigrationRequired
	}
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", ErrOwnerScopeMigrationRequired
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != unix.S_IFDIR || mode&0o022 != 0 || (uint32(stat.Uid) != 0 && uint32(stat.Uid) != uint32(os.Geteuid())) {
		unix.Close(fd)
		return nil, "", ErrOwnerScopeMigrationRequired
	}
	file := os.NewFile(uintptr(fd), "redevplugin-owner-scope-root")
	if file == nil {
		unix.Close(fd)
		return nil, "", ErrOwnerScopeMigrationRequired
	}
	identity := digestString(fmt.Sprintf("dev=%d;ino=%d;uid=%d;mode=%o", stat.Dev, stat.Ino, stat.Uid, mode&0o7777))
	return file, identity, nil
}

func snapshotRoot(root *os.File, exclusions map[string]struct{}) (rootSnapshot, error) {
	return snapshotDirectoryWithExclusions(root, exclusions)
}

func snapshotDirectory(root *os.File) (rootSnapshot, error) {
	return snapshotDirectoryWithExclusions(root, nil)
}

func snapshotDirectoryWithExclusions(root *os.File, exclusions map[string]struct{}) (rootSnapshot, error) {
	if root == nil {
		return rootSnapshot{}, ErrOwnerScopeMigrationRequired
	}
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return rootSnapshot{}, err
	}
	duplicate := os.NewFile(uintptr(fd), "redevplugin-snapshot-root")
	if duplicate == nil {
		unix.Close(fd)
		return rootSnapshot{}, ErrOwnerScopeMigrationRequired
	}
	defer duplicate.Close()
	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil {
		return rootSnapshot{}, err
	}
	entries := make([]snapshotEntry, 0, 64)
	var totalBytes int64
	if err := walkSnapshotDirectory(duplicate, "", exclusions, uint64(rootStat.Dev), uint32(rootStat.Uid), &entries, &totalBytes); err != nil {
		return rootSnapshot{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	raw, err := json.Marshal(entries)
	if err != nil {
		return rootSnapshot{}, err
	}
	return rootSnapshot{entries: entries, digest: digestBytes(raw)}, nil
}

func walkSnapshotDirectory(directory *os.File, prefix string, exclusions map[string]struct{}, rootDevice uint64, ownerUID uint32, entries *[]snapshotEntry, totalBytes *int64) error {
	listed, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Name() < listed[j].Name() })
	for _, item := range listed {
		name := item.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
			return ErrOwnerScopeMigrationRequired
		}
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		if _, excluded := exclusions[relative]; excluded {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		mode := uint32(stat.Mode)
		if uint64(stat.Dev) != rootDevice || uint32(stat.Uid) != ownerUID || mode&0o022 != 0 {
			return ErrOwnerScopeMigrationRequired
		}
		entry := snapshotEntry{
			Path: relative, Device: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: uint32(stat.Uid),
			Mode: mode & 0o7777, Size: stat.Size, Nlink: uint64(stat.Nlink),
		}
		switch mode & unix.S_IFMT {
		case unix.S_IFDIR:
			entry.Kind = "directory"
			entry.Size = 0
			entry.Nlink = 0
			*entries = append(*entries, entry)
			child, err := openDirectoryAt(int(directory.Fd()), name)
			if err != nil {
				return err
			}
			err = walkSnapshotDirectory(child, relative, exclusions, rootDevice, ownerUID, entries, totalBytes)
			_ = child.Close()
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			if stat.Nlink != 1 || stat.Size < 0 {
				return ErrOwnerScopeMigrationRequired
			}
			entry.Kind = "file"
			entry.SHA256, err = hashFileAt(int(directory.Fd()), name, stat.Size)
			if err != nil {
				return err
			}
			*totalBytes += stat.Size
			*entries = append(*entries, entry)
		default:
			return ErrOwnerScopeMigrationRequired
		}
		if len(*entries) > maxSnapshotEntries || *totalBytes > maxSnapshotBytes {
			return ErrOwnerScopeMigrationRequired
		}
	}
	return nil
}

func matchBuiltInInventory(root *os.File, snapshot rootSnapshot) (string, string, []migrationStoreV1, error) {
	matches := make([]builtInOwnerScopeInventory, 0, 1)
	corrupt := false
	for _, inventory := range builtInOwnerScopeInventories {
		if !snapshotMatchesInventoryLayout(snapshot, inventory) {
			continue
		}
		matched := true
		for _, database := range inventory.SQLiteDatabases {
			valid, err := validateSQLiteDatabase(root, database)
			if err != nil {
				corrupt = true
				matched = false
				break
			}
			if !valid {
				matched = false
				break
			}
		}
		if matched {
			matches = append(matches, inventory)
		}
	}
	if len(matches) > 1 {
		return "", "", nil, ErrOwnerScopeInventoryAmbiguous
	}
	if len(matches) == 0 {
		if corrupt {
			return "", "", nil, ErrOwnerScopeInventoryCorrupt
		}
		return "", "", nil, ErrOwnerScopeMigrationRequired
	}
	stores := []migrationStoreV1{
		{ID: "assets", Scope: "durable", Disposition: string(StoreDispositionQuarantine)},
		{ID: "db", Scope: "durable", Disposition: string(StoreDispositionQuarantine)},
		{ID: "storage", Scope: "durable", Disposition: string(StoreDispositionQuarantine)},
	}
	return matches[0].ID, matches[0].SHA256, stores, nil
}

func snapshotMatchesInventoryLayout(snapshot rootSnapshot, inventory builtInOwnerScopeInventory) bool {
	expectedDatabases := make(map[string]struct{}, len(inventory.SQLiteDatabases))
	for _, database := range inventory.SQLiteDatabases {
		expectedDatabases[strings.TrimPrefix(database.Path, "db/")] = struct{}{}
	}
	seenRoots := map[string]bool{}
	seenDatabases := make(map[string]bool, len(expectedDatabases))
	for _, entry := range snapshot.entries {
		parts := strings.Split(entry.Path, "/")
		if len(parts) == 1 {
			if entry.Kind != "directory" || (parts[0] != "assets" && parts[0] != "db" && parts[0] != "storage") {
				return false
			}
			seenRoots[parts[0]] = true
			continue
		}
		switch parts[0] {
		case "assets", "storage":
			continue
		case "db":
			if len(parts) != 2 || entry.Kind != "file" {
				return false
			}
			name := parts[1]
			if _, exists := expectedDatabases[name]; exists {
				seenDatabases[name] = true
				continue
			}
			if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
				mainName := strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), "-shm")
				if _, exists := expectedDatabases[mainName]; exists {
					continue
				}
			}
			return false
		default:
			return false
		}
	}
	return seenRoots["assets"] && seenRoots["db"] && seenRoots["storage"] && len(seenRoots) == 3 && len(seenDatabases) == len(expectedDatabases)
}

func validateSQLiteDatabase(root *os.File, expected builtInOwnerScopeSQLiteDatabase) (bool, error) {
	temporaryRoot, err := os.MkdirTemp("", "redevplugin-owner-scope-sqlite-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(temporaryRoot)

	name := filepath.Base(expected.Path)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		required := suffix == ""
		if err := copySQLiteInventoryFile(root, expected.Path+suffix, filepath.Join(temporaryRoot, name+suffix), required); err != nil {
			return false, err
		}
	}
	database, err := sql.Open("sqlite", filepath.Join(temporaryRoot, name))
	if err != nil {
		return false, err
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	if _, err := database.Exec(`PRAGMA query_only = ON`); err != nil {
		return false, err
	}
	var applicationID, userVersion int64
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return false, err
	}
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&userVersion); err != nil {
		return false, err
	}
	if applicationID != expected.ApplicationID || userVersion != expected.UserVersion {
		return false, nil
	}

	rows, err := database.Query(`SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		return false, err
	}
	objects := make([]sqliteSchemaObject, 0, expected.SchemaObjectCount)
	for rows.Next() {
		var object sqliteSchemaObject
		if err := rows.Scan(&object.Type, &object.Name, &object.TableName, &object.SQL); err != nil {
			rows.Close()
			return false, err
		}
		object.SQL = strings.Join(strings.Fields(object.SQL), " ")
		objects = append(objects, object)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	rawSchema, err := json.Marshal(objects)
	if err != nil {
		return false, err
	}
	if len(objects) != expected.SchemaObjectCount || digestBytes(rawSchema) != expected.SchemaSHA256 {
		return false, nil
	}
	for _, migration := range expected.MigrationVersions {
		migrationRows, err := database.Query(fmt.Sprintf(`SELECT version FROM %q ORDER BY version`, migration.Table))
		if err != nil {
			return false, err
		}
		versions := make([]int64, 0, len(migration.Versions))
		for migrationRows.Next() {
			var version int64
			if err := migrationRows.Scan(&version); err != nil {
				migrationRows.Close()
				return false, err
			}
			versions = append(versions, version)
		}
		if err := migrationRows.Err(); err != nil {
			migrationRows.Close()
			return false, err
		}
		if err := migrationRows.Close(); err != nil {
			return false, err
		}
		if !slices.Equal(versions, migration.Versions) {
			return false, nil
		}
	}
	return true, nil
}

func copySQLiteInventoryFile(root *os.File, sourcePath, destinationPath string, required bool) error {
	parts := strings.Split(sourcePath, "/")
	if len(parts) != 2 || parts[0] != "db" {
		return ErrOwnerScopeInventoryCorrupt
	}
	directory, err := openDirectoryAt(int(root.Fd()), parts[0])
	if err != nil {
		return err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), parts[1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if !required && errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	source := os.NewFile(uintptr(fd), sourcePath)
	if source == nil {
		unix.Close(fd)
		return ErrOwnerScopeInventoryCorrupt
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || (required && info.Size() < 1) || info.Size() > maxSnapshotBytes {
		return ErrOwnerScopeInventoryCorrupt
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(destination, io.LimitReader(source, maxSnapshotBytes+1))
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func statusFromJournal(journal migrationJournalV1) Status {
	stores := make([]StoreStatus, len(journal.Stores))
	for index, store := range journal.Stores {
		stores[index] = StoreStatus{ID: store.ID, Scope: store.Scope, Disposition: StoreDisposition(store.Disposition), Generation: store.Generation, Outcome: store.Outcome}
	}
	return Status{
		MigrationID: journal.MigrationID, RootIdentitySHA256: journal.RootIdentitySHA256,
		LegacySnapshotSHA256: journal.LegacySnapshotSHA256, InventoryID: journal.InventoryID, InventorySHA256: journal.InventorySHA256,
		State: MigrationState(journal.State), QuarantineID: quarantineIDFromWire(journal.QuarantineID), QuarantineSHA256: journal.QuarantineSHA256,
		FreshGenerationID: journal.FreshGenerationID, FreshGenerationSHA256: journal.FreshGenerationSHA256, Stores: stores,
	}
}

func decodeMigrationJournal(raw []byte) (migrationJournalV1, error) {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return migrationJournalV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal migrationJournalV1
	if err := decoder.Decode(&journal); err != nil {
		return migrationJournalV1{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return migrationJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	if journal.SchemaVersion != migrationSchemaVersion || !validOpaqueID(journal.MigrationID, "migration") ||
		!validSHA256(journal.RootIdentitySHA256) || !validSHA256(journal.LegacySnapshotSHA256) ||
		!validMigrationState(MigrationState(journal.State)) || !validMigrationJournalFields(journal) {
		return migrationJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	return journal, nil
}

func decodeCleanupJournal(raw []byte, migration migrationJournalV1) (cleanupJournalV1, error) {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return cleanupJournalV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cleanup cleanupJournalV1
	if err := decoder.Decode(&cleanup); err != nil {
		return cleanupJournalV1{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return cleanupJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	if cleanup.SchemaVersion != cleanupSchemaVersion || migration.State != string(StateFreshCommitted) || cleanup.MigrationID != migration.MigrationID || cleanup.RootIdentitySHA256 != migration.RootIdentitySHA256 ||
		cleanup.QuarantineID != migration.QuarantineID || cleanup.QuarantineSHA256 != migration.QuarantineSHA256 || !validCleanupState(CleanupState(cleanup.State)) ||
		!validOpaqueID(cleanup.MigrationID, "migration") || !validSHA256(cleanup.RootIdentitySHA256) || !validOpaqueID(cleanup.QuarantineID, "quarantine") ||
		!validSHA256(cleanup.QuarantineSHA256) || len(cleanup.Entries) == 0 || !snapshotEntriesCanonical(cleanup.Entries) {
		return cleanupJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	rawEntries, err := json.Marshal(cleanup.Entries)
	if err != nil || digestBytes(rawEntries) != cleanup.QuarantineSHA256 {
		return cleanupJournalV1{}, ErrOwnerScopeJournalCorrupt
	}
	return cleanup, nil
}

func snapshotEntriesCanonical(entries []snapshotEntry) bool {
	if len(entries) > maxSnapshotEntries {
		return false
	}
	var totalBytes int64
	for index, entry := range entries {
		if !validSnapshotPath(entry.Path) || entry.Inode == 0 || entry.Mode > 0o7777 || entry.Mode&0o022 != 0 ||
			(index > 0 && entries[index-1].Path >= entry.Path) {
			return false
		}
		switch entry.Kind {
		case "file":
			if entry.Size < 0 || entry.Size > maxSnapshotBytes || entry.Nlink != 1 || !validSHA256(entry.SHA256) {
				return false
			}
			if totalBytes > maxSnapshotBytes-entry.Size {
				return false
			}
			totalBytes += entry.Size
		case "directory":
			if entry.Size != 0 || entry.Nlink != 0 || entry.SHA256 != "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validMigrationJournalFields(journal migrationJournalV1) bool {
	state := MigrationState(journal.State)
	legacy := journal.InventoryID != "" || journal.InventorySHA256 != "" || len(journal.Stores) != 0
	if legacy {
		if !validInventoryID(journal.InventoryID) || !validSHA256(journal.InventorySHA256) || !validMigrationStores(journal.Stores) {
			return false
		}
	} else if state != StateFreshPrepared && state != StateFreshCommitted && state != StateReconcileRequired && state != StateFailed {
		return false
	}

	validQuarantine := validOpaqueID(journal.QuarantineID, "quarantine") && validSHA256(journal.QuarantineSHA256)
	validFresh := validOpaqueID(journal.FreshGenerationID, "generation") && validSHA256(journal.FreshGenerationSHA256)
	switch state {
	case StatePrepared:
		return legacy && journal.QuarantineID == "" && journal.QuarantineSHA256 == "" && journal.FreshGenerationID == "" && journal.FreshGenerationSHA256 == ""
	case StateQuarantineWriting:
		return legacy && validOpaqueID(journal.QuarantineID, "quarantine") && journal.QuarantineSHA256 == "" && journal.FreshGenerationID == "" && journal.FreshGenerationSHA256 == ""
	case StateQuarantineCommitted:
		return legacy && validQuarantine && journal.FreshGenerationID == "" && journal.FreshGenerationSHA256 == ""
	case StateFreshPrepared, StateFreshCommitted:
		if !validFresh {
			return false
		}
		return !legacy || validQuarantine
	case StateReconcileRequired, StateFailed:
		return optionalOpaqueAndDigest(journal.QuarantineID, journal.QuarantineSHA256, "quarantine") &&
			optionalOpaqueAndDigest(journal.FreshGenerationID, journal.FreshGenerationSHA256, "generation")
	default:
		return false
	}
}

func validMigrationStores(stores []migrationStoreV1) bool {
	if len(stores) == 0 || len(stores) > 64 {
		return false
	}
	for index, store := range stores {
		if !validInventoryID(store.ID) || (index > 0 && stores[index-1].ID >= store.ID) || len(store.Generation) > 128 || len(store.Outcome) > 128 {
			return false
		}
		switch store.Scope {
		case "durable":
			if store.Disposition != string(StoreDispositionQuarantine) {
				return false
			}
		case "session", "transient":
			if store.Disposition != string(StoreDispositionTerminate) {
				return false
			}
		default:
			return false
		}
		if store.Generation != "" && !validOpaqueID(store.Generation, "generation") {
			return false
		}
	}
	return true
}

func optionalOpaqueAndDigest(id, digest, prefix string) bool {
	return (id == "" && digest == "") || (validOpaqueID(id, prefix) && (digest == "" || validSHA256(digest)))
}

func validOpaqueID(value, prefix string) bool {
	wantedPrefix := prefix + "_"
	if !strings.HasPrefix(value, wantedPrefix) || len(value) != len(wantedPrefix)+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, wantedPrefix))
	return err == nil && value == strings.ToLower(value)
}

func validInventoryID(value string) bool {
	if len(value) < 2 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSnapshotPath(path string) bool {
	if path == "" || len(path) > 4096 || strings.Contains(path, "\\") || strings.HasPrefix(path, "/") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func snapshotIsExactSubset(current, expected []snapshotEntry) bool {
	expectedByPath := make(map[string]snapshotEntry, len(expected))
	for _, entry := range expected {
		expectedByPath[entry.Path] = entry
	}
	for _, entry := range current {
		if expectedEntry, ok := expectedByPath[entry.Path]; !ok || expectedEntry != entry {
			return false
		}
	}
	return true
}

func validMigrationState(state MigrationState) bool {
	switch state {
	case StatePrepared, StateQuarantineWriting, StateQuarantineCommitted, StateFreshPrepared, StateFreshCommitted, StateReconcileRequired, StateFailed:
		return true
	default:
		return false
	}
}

func validCleanupState(state CleanupState) bool {
	switch state {
	case CleanupStateDeletePrepared, CleanupStateDeleting, CleanupStateReconcileRequired, CleanupStateDeleted:
		return true
	default:
		return false
	}
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrOwnerScopeJournalCorrupt
				}
				if _, exists := seen[key]; exists {
					return ErrOwnerScopeJournalCorrupt
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return ErrOwnerScopeJournalCorrupt
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return ErrOwnerScopeJournalCorrupt
			}
		default:
			return ErrOwnerScopeJournalCorrupt
		}
		return nil
	}
	if err := walk(); err != nil {
		return ErrOwnerScopeJournalCorrupt
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrOwnerScopeJournalCorrupt
	}
	return nil
}

func preparedSnapshotExclusions() map[string]struct{} {
	return map[string]struct{}{
		MigrationJournalName: {},
	}
}

func readRootFile(root *os.File, name string, maxBytes int64) ([]byte, error) {
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, ErrOwnerScopeJournalCorrupt
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes {
		return nil, ErrOwnerScopeJournalCorrupt
	}
	return io.ReadAll(io.LimitReader(file, maxBytes+1))
}

func writeAtomicRootFile(root *os.File, name string, value []byte, mode uint32) error {
	temporary, err := newOpaqueID("tmp")
	if err != nil {
		return err
	}
	temporary = "." + name + "." + temporary
	fd, err := unix.Openat(int(root.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		unix.Close(fd)
		return ErrOwnerScopeJournalCorrupt
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = unix.Unlinkat(int(root.Fd()), temporary, 0)
		}
	}()
	if _, err := file.Write(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(int(root.Fd()), temporary, int(root.Fd()), name); err != nil {
		return err
	}
	cleanup = false
	return unix.Fsync(int(root.Fd()))
}

func moveStoreIntoQuarantine(rootFD, quarantineFD int, name string) error {
	var source unix.Stat_t
	sourceErr := unix.Fstatat(rootFD, name, &source, unix.AT_SYMLINK_NOFOLLOW)
	var destination unix.Stat_t
	destinationErr := unix.Fstatat(quarantineFD, name, &destination, unix.AT_SYMLINK_NOFOLLOW)
	if sourceErr == nil && destinationErr == nil {
		return ErrOwnerScopeSnapshotChanged
	}
	if errors.Is(sourceErr, unix.ENOENT) && destinationErr == nil {
		return nil
	}
	if sourceErr != nil {
		return sourceErr
	}
	if !errors.Is(destinationErr, unix.ENOENT) {
		return destinationErr
	}
	return unix.Renameat(rootFD, name, quarantineFD, name)
}

func openDirectoryAt(parentFD int, name string) (*os.File, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, ErrOwnerScopeMigrationRequired
	}
	return file, nil
}

func ensureDirectoryAt(parentFD int, name string, mode uint32) error {
	if err := unix.Mkdirat(parentFD, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR || uint32(stat.Mode)&0o022 != 0 {
		return ErrOwnerScopeMigrationRequired
	}
	return nil
}

func hashFileAt(parentFD int, name string, size int64) (string, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	hasher := sha256.New()
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < size; {
		chunk := int64(len(buffer))
		if remaining := size - offset; remaining < chunk {
			chunk = remaining
		}
		read, err := unix.Pread(fd, buffer[:chunk], offset)
		if err != nil {
			return "", err
		}
		if read == 0 {
			return "", io.ErrUnexpectedEOF
		}
		_, _ = hasher.Write(buffer[:read])
		offset += int64(read)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func deleteDirectoryContents(directoryFD int, prefix string, expected map[string]snapshotEntry) error {
	fd, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "quarantine-delete")
	if directory == nil {
		unix.Close(fd)
		return ErrOwnerScopeMigrationRequired
	}
	listed, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	for _, item := range listed {
		name := item.Name()
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		expectedEntry, exists := expected[relative]
		if !exists || !snapshotStatMatches(expectedEntry, stat) {
			return ErrOwnerScopeSnapshotChanged
		}
		switch uint32(stat.Mode) & unix.S_IFMT {
		case unix.S_IFDIR:
			child, err := openDirectoryAt(directoryFD, name)
			if err != nil {
				return err
			}
			var opened unix.Stat_t
			if err := unix.Fstat(int(child.Fd()), &opened); err != nil || !snapshotStatMatches(expectedEntry, opened) {
				_ = child.Close()
				return ErrOwnerScopeSnapshotChanged
			}
			err = deleteDirectoryContents(int(child.Fd()), relative, expected)
			_ = child.Close()
			if err != nil {
				return err
			}
			if err := unix.Unlinkat(directoryFD, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
		case unix.S_IFREG:
			if stat.Nlink != 1 {
				return ErrOwnerScopeSnapshotChanged
			}
			if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
				return err
			}
		default:
			return ErrOwnerScopeSnapshotChanged
		}
	}
	return unix.Fsync(directoryFD)
}

func snapshotStatMatches(expected snapshotEntry, actual unix.Stat_t) bool {
	mode := uint32(actual.Mode)
	if uint64(actual.Dev) != expected.Device || uint64(actual.Ino) != expected.Inode || uint32(actual.Uid) != expected.UID || mode&0o7777 != expected.Mode {
		return false
	}
	switch expected.Kind {
	case "directory":
		return mode&unix.S_IFMT == unix.S_IFDIR
	case "file":
		return mode&unix.S_IFMT == unix.S_IFREG && actual.Size == expected.Size && uint64(actual.Nlink) == expected.Nlink
	default:
		return false
	}
}

func newOpaqueID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}

func digestString(value string) string { return digestBytes([]byte(value)) }

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
