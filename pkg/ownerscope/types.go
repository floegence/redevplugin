// Package ownerscope provides the fail-closed migration boundary for durable
// plugin state created before owner-scoped generations were mandatory.
package ownerscope

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
)

const (
	MigrationJournalName = ".redevplugin-owner-scope-migration-v1.json"
	CleanupJournalName   = ".redevplugin-quarantine-cleanup-v1.json"
)

var (
	ErrOwnerScopeMigrationRequired  = errors.New("owner scope migration is required")
	ErrOwnerScopeInventoryAmbiguous = errors.New("owner scope inventory is ambiguous")
	ErrOwnerScopeInventoryCorrupt   = errors.New("owner scope legacy inventory is corrupt")
	ErrOwnerScopeJournalCorrupt     = errors.New("owner scope migration journal is corrupt")
	ErrOwnerScopeSnapshotChanged    = errors.New("owner scope migration snapshot changed")
	ErrOwnerScopeTransition         = errors.New("owner scope migration transition is invalid")
	ErrLegacyContainmentRequired    = errors.New("legacy containment evidence is required")
	ErrInvalidQuarantineID          = errors.New("quarantine id is invalid")
	ErrOwnerScopeUnsupported        = errors.New("owner scope migration is unsupported on this platform")
)

type MigrationState string

const (
	StatePrepared            MigrationState = "prepared"
	StateQuarantineWriting   MigrationState = "quarantine_writing"
	StateQuarantineCommitted MigrationState = "quarantine_committed"
	StateFreshPrepared       MigrationState = "fresh_prepared"
	StateFreshCommitted      MigrationState = "fresh_committed"
	StateReconcileRequired   MigrationState = "reconcile_required"
	StateFailed              MigrationState = "failed"
)

type CleanupState string

const (
	CleanupStateNone              CleanupState = ""
	CleanupStateDeletePrepared    CleanupState = "delete_prepared"
	CleanupStateDeleting          CleanupState = "deleting"
	CleanupStateReconcileRequired CleanupState = "delete_reconcile_required"
	CleanupStateDeleted           CleanupState = "deleted"
)

type StoreDisposition string

const (
	StoreDispositionQuarantine StoreDisposition = "quarantine"
	StoreDispositionTerminate  StoreDisposition = "terminate"
)

type StoreStatus struct {
	ID          string
	Scope       string
	Disposition StoreDisposition
	Generation  string
	Outcome     string
}

type QuarantineID struct {
	value string
}

func ParseQuarantineID(value string) (QuarantineID, error) {
	const prefix = "quarantine_"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+32 || value != strings.ToLower(value) {
		return QuarantineID{}, ErrInvalidQuarantineID
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value, prefix)); err != nil {
		return QuarantineID{}, ErrInvalidQuarantineID
	}
	return QuarantineID{value: value}, nil
}

func (id QuarantineID) String() string { return id.value }
func (id QuarantineID) IsZero() bool   { return id.value == "" }

func quarantineIDFromWire(value string) QuarantineID {
	id, _ := ParseQuarantineID(value)
	return id
}

type Status struct {
	MigrationID           string
	RootIdentitySHA256    string
	LegacySnapshotSHA256  string
	InventoryID           string
	InventorySHA256       string
	State                 MigrationState
	QuarantineID          QuarantineID
	QuarantineSHA256      string
	FreshGenerationID     string
	FreshGenerationSHA256 string
	CleanupState          CleanupState
	Stores                []StoreStatus
}

func cloneStatus(status Status) Status {
	status.Stores = slices.Clone(status.Stores)
	return status
}

type LegacyContainmentRequest struct {
	migrationID        string
	rootIdentitySHA256 string
	quarantineID       QuarantineID
	quarantineSHA256   string
}

func (request LegacyContainmentRequest) MigrationID() string { return request.migrationID }
func (request LegacyContainmentRequest) RootIdentitySHA256() string {
	return request.rootIdentitySHA256
}
func (request LegacyContainmentRequest) QuarantineID() QuarantineID { return request.quarantineID }
func (request LegacyContainmentRequest) QuarantineSHA256() string   { return request.quarantineSHA256 }

func (request LegacyContainmentRequest) valid() bool {
	return request.migrationID != "" && request.rootIdentitySHA256 != "" && !request.quarantineID.IsZero() && request.quarantineSHA256 != ""
}

type LegacyContainmentEvidence struct {
	request LegacyContainmentRequest
}

func NewLegacyContainmentEvidence(request LegacyContainmentRequest) LegacyContainmentEvidence {
	if !request.valid() {
		return LegacyContainmentEvidence{}
	}
	return LegacyContainmentEvidence{request: request}
}

type LegacyContainmentVerifier interface {
	VerifyLegacyContainment(context.Context, LegacyContainmentRequest) (LegacyContainmentEvidence, error)
}

type OwnerScopeMigrationOptions struct {
	Containment LegacyContainmentVerifier
}

type OwnerScopeMigration struct {
	mu      sync.Mutex
	root    *os.File
	options OwnerScopeMigrationOptions
	journal migrationJournalV1
	cleanup cleanupJournalV1
	status  Status
	closed  bool
}

// OwnerScopeGeneration is the committed durable state generation prepared for
// host initialization. Path is the only directory where the host should create
// ReDevPlugin-owned durable state.
type OwnerScopeGeneration struct {
	Path   string
	Status Status
}

// PrepareOwnerScopeGeneration opens or resumes the owner-scope migration at
// rootPath and returns its committed active generation. Recognized unowned
// legacy state is quarantined and retained; this function never deletes it.
// Unknown, corrupt, failed, or reconcile-required state remains fail closed.
func PrepareOwnerScopeGeneration(ctx context.Context, rootPath string) (generation OwnerScopeGeneration, err error) {
	if ctx == nil {
		return OwnerScopeGeneration{}, ErrOwnerScopeTransition
	}
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" {
		return OwnerScopeGeneration{}, ErrOwnerScopeMigrationRequired
	}
	root, err := os.Open(rootPath)
	if err != nil {
		return OwnerScopeGeneration{}, err
	}
	migration, openErr := OpenOwnerScopeMigration(root, OwnerScopeMigrationOptions{})
	closeRootErr := root.Close()
	if openErr != nil || closeRootErr != nil {
		if migration != nil {
			_ = migration.Close()
		}
		return OwnerScopeGeneration{}, errors.Join(openErr, closeRootErr)
	}
	defer func() {
		err = errors.Join(err, migration.Close())
	}()

	generation.Status = migration.Status()
	switch generation.Status.State {
	case StatePrepared, StateQuarantineWriting:
		generation.Status, err = migration.QuarantineUnownedLegacy(ctx)
		if err != nil {
			return generation, err
		}
	case StateQuarantineCommitted, StateFreshPrepared, StateFreshCommitted:
	default:
		return generation, ErrOwnerScopeTransition
	}

	switch generation.Status.State {
	case StateQuarantineCommitted, StateFreshPrepared:
		generation.Status, err = migration.CommitFreshGeneration(ctx)
		if err != nil {
			return generation, err
		}
	case StateFreshCommitted:
	default:
		return generation, ErrOwnerScopeTransition
	}

	generation.Path, err = migration.ActiveGenerationPath(rootPath)
	return generation, err
}

func (migration *OwnerScopeMigration) Status() Status {
	if migration == nil {
		return Status{}
	}
	migration.mu.Lock()
	defer migration.mu.Unlock()
	return cloneStatus(migration.status)
}
