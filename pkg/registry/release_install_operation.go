package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

type ReleaseInstallOperationStatus string

const (
	ReleaseInstallQueued      ReleaseInstallOperationStatus = "queued"
	ReleaseInstallRunning     ReleaseInstallOperationStatus = "running"
	ReleaseInstallReconciling ReleaseInstallOperationStatus = "reconciling"
	ReleaseInstallSucceeded   ReleaseInstallOperationStatus = "succeeded"
	ReleaseInstallFailed      ReleaseInstallOperationStatus = "failed"
)

type ReleaseInstallProgressKind string

const (
	ReleaseInstallProgressIndeterminate ReleaseInstallProgressKind = "indeterminate"
	ReleaseInstallProgressItems         ReleaseInstallProgressKind = "items"
	ReleaseInstallProgressBytes         ReleaseInstallProgressKind = "bytes"
)

type ReleaseInstallProgress struct {
	Kind      ReleaseInstallProgressKind `json:"kind"`
	Completed int64                      `json:"completed,omitempty"`
	Total     int64                      `json:"total,omitempty"`
}

type ReleaseInstallFailure struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

// ReleaseInstallIdentity is the immutable signed-release coordinate required
// to reconcile an interrupted installation without retaining a source URL.
type ReleaseInstallIdentity struct {
	SourceID              string `json:"source_id"`
	Channel               string `json:"channel"`
	ReleaseMetadataRef    string `json:"release_metadata_ref"`
	ReleaseMetadataSHA256 string `json:"release_metadata_sha256"`
	PublisherID           string `json:"publisher_id"`
	PluginID              string `json:"plugin_id"`
	Version               string `json:"version"`
	PackageSHA256         string `json:"package_sha256"`
	ManifestSHA256        string `json:"manifest_sha256"`
	EntriesSHA256         string `json:"entries_sha256"`
}

type StartReleaseInstallOperationRequest struct {
	RequestID        string                 `json:"request_id"`
	OperationID      string                 `json:"operation_id"`
	PluginInstanceID string                 `json:"plugin_instance_id"`
	Release          ReleaseInstallIdentity `json:"release"`
	Now              time.Time              `json:"-"`
}

type UpdateReleaseInstallOperationRequest struct {
	OperationID      string
	ExpectedRevision uint64
	Status           ReleaseInstallOperationStatus
	Phase            string
	Progress         ReleaseInstallProgress
	Attempt          int
	RetryAfterMS     int64
	MutationOutcome  mutation.Outcome
	Failure          *ReleaseInstallFailure
	PluginRecord     *PluginRecord
	Now              time.Time
}

type ReleaseInstallOperation struct {
	RequestID        string                        `json:"request_id"`
	OperationID      string                        `json:"operation_id"`
	PluginInstanceID string                        `json:"plugin_instance_id"`
	RequestSHA256    string                        `json:"request_sha256"`
	Status           ReleaseInstallOperationStatus `json:"status"`
	Phase            string                        `json:"phase"`
	Progress         ReleaseInstallProgress        `json:"progress"`
	Attempt          int                           `json:"attempt"`
	RetryAfterMS     int64                         `json:"retry_after_ms"`
	MutationOutcome  mutation.Outcome              `json:"mutation_outcome"`
	Failure          *ReleaseInstallFailure        `json:"failure,omitempty"`
	PluginRecord     *PluginRecord                 `json:"plugin_record,omitempty"`
	CreatedAt        time.Time                     `json:"created_at"`
	UpdatedAt        time.Time                     `json:"updated_at"`
	TerminalAt       *time.Time                    `json:"terminal_at,omitempty"`
	Revision         uint64                        `json:"-"`
	Release          ReleaseInstallIdentity        `json:"-"`
}

type ReleaseInstallOperationStore interface {
	StartReleaseInstallOperation(context.Context, StartReleaseInstallOperationRequest) (ReleaseInstallOperation, bool, error)
	UpdateReleaseInstallOperation(context.Context, UpdateReleaseInstallOperationRequest) (ReleaseInstallOperation, error)
	GetReleaseInstallOperation(context.Context, string) (ReleaseInstallOperation, error)
	GetReleaseInstallOperationByRequest(context.Context, string) (ReleaseInstallOperation, error)
	ListReleaseInstallOperations(context.Context) ([]ReleaseInstallOperation, error)
}

var (
	ErrReleaseInstallOperationNotFound = errors.New("release install operation not found")
	ErrReleaseInstallOperationConflict = errors.New("release install operation conflict")
	ErrInvalidReleaseInstallOperation  = errors.New("invalid release install operation")
)

type releaseInstallOperationReceipt struct {
	OwnerEnvHash string
	Request      StartReleaseInstallOperationRequest
	Operation    ReleaseInstallOperation
}

func (s *MemoryStore) StartReleaseInstallOperation(ctx context.Context, req StartReleaseInstallOperationRequest) (ReleaseInstallOperation, bool, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	requestSHA256, err := releaseInstallRequestSHA256(req)
	if err != nil {
		return ReleaseInstallOperation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	requestKey := releaseInstallRequestKey(ownerEnvHash, req.RequestID)
	if receipt, ok := s.releaseInstallOps[requestKey]; ok {
		if receipt.Operation.RequestSHA256 != requestSHA256 {
			return ReleaseInstallOperation{}, false, ErrReleaseInstallOperationConflict
		}
		cloned, cloneErr := cloneReleaseInstallOperation(receipt.Operation)
		return cloned, false, cloneErr
	}
	for _, receipt := range s.releaseInstallOps {
		if receipt.OwnerEnvHash != ownerEnvHash {
			continue
		}
		if receipt.Operation.OperationID == req.OperationID {
			return ReleaseInstallOperation{}, false, ErrReleaseInstallOperationConflict
		}
		if receipt.Operation.PluginInstanceID == req.PluginInstanceID && releaseInstallOperationActive(receipt.Operation.Status) {
			cloned, cloneErr := cloneReleaseInstallOperation(receipt.Operation)
			return cloned, false, cloneErr
		}
	}
	now := normalizedOperationTime(req.Now)
	op := ReleaseInstallOperation{
		RequestID: req.RequestID, OperationID: req.OperationID, PluginInstanceID: req.PluginInstanceID,
		RequestSHA256: requestSHA256, Status: ReleaseInstallQueued, Phase: "queued",
		Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate}, Attempt: 1,
		MutationOutcome: mutation.OutcomeNotCommitted, CreatedAt: now, UpdatedAt: now, Revision: 1, Release: req.Release,
	}
	s.releaseInstallOps[requestKey] = releaseInstallOperationReceipt{OwnerEnvHash: ownerEnvHash, Request: req, Operation: op}
	cloned, err := cloneReleaseInstallOperation(op)
	return cloned, true, err
}

func (s *MemoryStore) UpdateReleaseInstallOperation(ctx context.Context, req UpdateReleaseInstallOperationRequest) (ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, receipt, ok := findMemoryReleaseInstallOperation(s.releaseInstallOps, ownerEnvHash, req.OperationID)
	if !ok {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationNotFound
	}
	updated, err := applyReleaseInstallOperationUpdate(receipt.Operation, req)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	receipt.Operation = updated
	s.releaseInstallOps[key] = receipt
	return cloneReleaseInstallOperation(updated)
}

func (s *MemoryStore) GetReleaseInstallOperation(ctx context.Context, operationID string) (ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, receipt, ok := findMemoryReleaseInstallOperation(s.releaseInstallOps, ownerEnvHash, operationID)
	if !ok {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationNotFound
	}
	return cloneReleaseInstallOperation(receipt.Operation)
}

func (s *MemoryStore) GetReleaseInstallOperationByRequest(ctx context.Context, requestID string) (ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, ok := s.releaseInstallOps[releaseInstallRequestKey(ownerEnvHash, requestID)]
	if !ok {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationNotFound
	}
	return cloneReleaseInstallOperation(receipt.Operation)
}

func (s *MemoryStore) ListReleaseInstallOperations(ctx context.Context) ([]ReleaseInstallOperation, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]ReleaseInstallOperation, 0)
	for _, receipt := range s.releaseInstallOps {
		if receipt.OwnerEnvHash != ownerEnvHash {
			continue
		}
		cloned, err := cloneReleaseInstallOperation(receipt.Operation)
		if err != nil {
			return nil, err
		}
		result = append(result, cloned)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].OperationID < result[j].OperationID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func releaseInstallRequestSHA256(req StartReleaseInstallOperationRequest) (string, error) {
	if err := validateStartReleaseInstallOperation(req); err != nil {
		return "", err
	}
	canonical := struct {
		RequestID        string                 `json:"request_id"`
		PluginInstanceID string                 `json:"plugin_instance_id"`
		Release          ReleaseInstallIdentity `json:"release"`
	}{RequestID: req.RequestID, PluginInstanceID: req.PluginInstanceID, Release: req.Release}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateStartReleaseInstallOperation(req StartReleaseInstallOperationRequest) error {
	values := map[string]string{
		"request_id": req.RequestID, "operation_id": req.OperationID, "plugin_instance_id": req.PluginInstanceID,
		"source_id": req.Release.SourceID, "channel": req.Release.Channel, "release_metadata_ref": req.Release.ReleaseMetadataRef,
		"release_metadata_sha256": req.Release.ReleaseMetadataSHA256, "publisher_id": req.Release.PublisherID,
		"plugin_id": req.Release.PluginID, "version": req.Release.Version,
		"package_sha256": req.Release.PackageSHA256, "manifest_sha256": req.Release.ManifestSHA256,
		"entries_sha256": req.Release.EntriesSHA256,
	}
	for name, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%w: %s is required and must be canonical", ErrInvalidReleaseInstallOperation, name)
		}
	}
	for name, digest := range map[string]string{
		"release_metadata_sha256": req.Release.ReleaseMetadataSHA256,
		"package_sha256":          req.Release.PackageSHA256,
		"manifest_sha256":         req.Release.ManifestSHA256,
		"entries_sha256":          req.Release.EntriesSHA256,
	} {
		if !validExternalPackageConfirmationDigest(digest) {
			return fmt.Errorf("%w: %s must be a canonical sha256 digest", ErrInvalidReleaseInstallOperation, name)
		}
	}
	return nil
}

func applyReleaseInstallOperationUpdate(current ReleaseInstallOperation, req UpdateReleaseInstallOperationRequest) (ReleaseInstallOperation, error) {
	if req.ExpectedRevision == 0 || req.ExpectedRevision != current.Revision || strings.TrimSpace(req.OperationID) == "" || req.OperationID != current.OperationID {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationConflict
	}
	if !validReleaseInstallTransition(current.Status, req.Status) || strings.TrimSpace(req.Phase) == "" {
		return ReleaseInstallOperation{}, ErrInvalidReleaseInstallOperation
	}
	if err := validateReleaseInstallProgress(req.Progress); err != nil {
		return ReleaseInstallOperation{}, err
	}
	terminal := req.Status == ReleaseInstallSucceeded || req.Status == ReleaseInstallFailed
	if terminal != (req.Failure != nil || req.PluginRecord != nil) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: terminal operation requires exactly one result", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == ReleaseInstallSucceeded && (req.PluginRecord == nil || req.Failure != nil || req.MutationOutcome != mutation.OutcomeCommitted) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: successful operation requires committed plugin record", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == ReleaseInstallFailed && (req.Failure == nil || req.PluginRecord != nil || strings.TrimSpace(req.Failure.Code) == "") {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: failed operation requires safe failure code", ErrInvalidReleaseInstallOperation)
	}
	now := normalizedOperationTime(req.Now)
	if now.Before(current.UpdatedAt) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: update time moved backwards", ErrInvalidReleaseInstallOperation)
	}
	current.Status, current.Phase, current.Progress = req.Status, req.Phase, req.Progress
	current.Attempt, current.RetryAfterMS, current.MutationOutcome = req.Attempt, req.RetryAfterMS, req.MutationOutcome
	current.Failure, current.PluginRecord, current.UpdatedAt = req.Failure, req.PluginRecord, now
	current.Revision++
	if terminal {
		terminalAt := now
		current.TerminalAt = &terminalAt
	}
	return current, nil
}

func validReleaseInstallTransition(from, to ReleaseInstallOperationStatus) bool {
	switch from {
	case ReleaseInstallQueued:
		return to == ReleaseInstallRunning || to == ReleaseInstallReconciling || to == ReleaseInstallFailed
	case ReleaseInstallRunning:
		return to == ReleaseInstallRunning || to == ReleaseInstallSucceeded || to == ReleaseInstallFailed
	case ReleaseInstallReconciling:
		return to == ReleaseInstallSucceeded || to == ReleaseInstallFailed
	default:
		return false
	}
}

func validateReleaseInstallProgress(progress ReleaseInstallProgress) error {
	switch progress.Kind {
	case ReleaseInstallProgressIndeterminate:
		if progress.Completed != 0 || progress.Total != 0 {
			return fmt.Errorf("%w: indeterminate progress cannot contain counters", ErrInvalidReleaseInstallOperation)
		}
	case ReleaseInstallProgressItems, ReleaseInstallProgressBytes:
		if progress.Completed < 0 || progress.Total <= 0 || progress.Completed > progress.Total {
			return fmt.Errorf("%w: progress counters are invalid", ErrInvalidReleaseInstallOperation)
		}
	default:
		return fmt.Errorf("%w: progress kind is invalid", ErrInvalidReleaseInstallOperation)
	}
	return nil
}

func releaseInstallOperationActive(status ReleaseInstallOperationStatus) bool {
	return status == ReleaseInstallQueued || status == ReleaseInstallRunning || status == ReleaseInstallReconciling
}

func normalizedOperationTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func releaseInstallRequestKey(ownerEnvHash, requestID string) string {
	return ownerEnvHash + "\x00" + requestID
}

func findMemoryReleaseInstallOperation(values map[string]releaseInstallOperationReceipt, ownerEnvHash, operationID string) (string, releaseInstallOperationReceipt, bool) {
	for key, receipt := range values {
		if receipt.OwnerEnvHash == ownerEnvHash && receipt.Operation.OperationID == operationID {
			return key, receipt, true
		}
	}
	return "", releaseInstallOperationReceipt{}, false
}

func cloneReleaseInstallOperation(value ReleaseInstallOperation) (ReleaseInstallOperation, error) {
	cloned := value
	if value.Failure != nil {
		failure := *value.Failure
		cloned.Failure = &failure
	}
	if value.PluginRecord != nil {
		record, err := clonePluginRecord(*value.PluginRecord)
		if err != nil {
			return ReleaseInstallOperation{}, err
		}
		cloned.PluginRecord = &record
	}
	if value.TerminalAt != nil {
		terminalAt := *value.TerminalAt
		cloned.TerminalAt = &terminalAt
	}
	return cloned, nil
}
