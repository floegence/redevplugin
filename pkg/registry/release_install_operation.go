package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/execution"
	"github.com/floegence/redevplugin/pkg/mutation"
)

const (
	ReleaseInstallNextActionApprovePermissions = "approve_permissions"
	ReleaseInstallNextActionRetryActivation    = "retry_activation"
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

type ReleaseInstallPhaseDiagnostic struct {
	Phase        string                 `json:"phase"`
	ArtifactRole string                 `json:"artifact_role,omitempty"`
	Attempt      int                    `json:"attempt"`
	Progress     ReleaseInstallProgress `json:"progress"`
	CacheHit     bool                   `json:"cache_hit"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	DurationMS   int64                  `json:"duration_ms,omitempty"`
}

type ReleaseInstallFailure struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

type ReleaseInstallActivationMode string

const (
	ReleaseInstallActivationAutomatic ReleaseInstallActivationMode = "automatic"
	ReleaseInstallActivationRequested ReleaseInstallActivationMode = "requested"
	ReleaseInstallActivationDisabled  ReleaseInstallActivationMode = "disabled"
)

type ReleaseInstallActivationStatus string

const (
	ReleaseInstallActivationPending        ReleaseInstallActivationStatus = "pending"
	ReleaseInstallActivationEnabled        ReleaseInstallActivationStatus = "enabled"
	ReleaseInstallActivationNeedsAttention ReleaseInstallActivationStatus = "needs_attention"
	ReleaseInstallActivationNotRequested   ReleaseInstallActivationStatus = "not_requested"
)

type ReleaseInstallActivationRequest struct {
	Mode                  ReleaseInstallActivationMode `json:"mode"`
	ApprovedPermissionIDs []string                     `json:"approved_permission_ids,omitempty"`
}

type ReleaseInstallActivation struct {
	Status               ReleaseInstallActivationStatus `json:"status"`
	MissingPermissionIDs []string                       `json:"missing_permission_ids,omitempty"`
	NextAction           string                         `json:"next_action,omitempty"`
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
	RequestID        string                          `json:"request_id"`
	ExecutionID      string                          `json:"execution_id"`
	PluginInstanceID string                          `json:"plugin_instance_id"`
	Release          ReleaseInstallIdentity          `json:"release"`
	Activation       ReleaseInstallActivationRequest `json:"activation"`
	Now              time.Time                       `json:"-"`
}

type UpdateReleaseInstallOperationRequest struct {
	ExecutionID     string
	ExpectedCursor  uint64
	Status          string
	Phase           string
	Progress        ReleaseInstallProgress
	ArtifactRole    string
	CacheHit        bool
	Attempt         int
	RetryAfterMS    int64
	MutationOutcome mutation.Outcome
	Failure         *ReleaseInstallFailure
	PluginRecord    *PluginRecord
	Activation      ReleaseInstallActivation
	Now             time.Time
}

type ReleaseInstallOperation struct {
	Execution         execution.Execution             `json:"-"`
	RequestID         string                          `json:"request_id"`
	PluginInstanceID  string                          `json:"plugin_instance_id"`
	RequestSHA256     string                          `json:"request_sha256"`
	Phase             string                          `json:"phase"`
	Progress          ReleaseInstallProgress          `json:"progress"`
	Attempt           int                             `json:"attempt"`
	RetryAfterMS      int64                           `json:"retry_after_ms"`
	MutationOutcome   mutation.Outcome                `json:"mutation_outcome"`
	Failure           *ReleaseInstallFailure          `json:"failure,omitempty"`
	PluginRecord      *PluginRecord                   `json:"plugin_record,omitempty"`
	Activation        ReleaseInstallActivation        `json:"activation"`
	PhaseDiagnostics  []ReleaseInstallPhaseDiagnostic `json:"phase_diagnostics"`
	Release           ReleaseInstallIdentity          `json:"-"`
	ActivationRequest ReleaseInstallActivationRequest `json:"-"`
}

var (
	ErrReleaseInstallOperationNotFound = errors.New("release install operation not found")
	ErrReleaseInstallOperationConflict = errors.New("release install operation conflict")
	ErrInvalidReleaseInstallOperation  = errors.New("invalid release install operation")
)

func releaseInstallRequestSHA256(req StartReleaseInstallOperationRequest) (string, error) {
	if err := validateStartReleaseInstallOperation(req); err != nil {
		return "", err
	}
	canonical := struct {
		RequestID        string                          `json:"request_id"`
		PluginInstanceID string                          `json:"plugin_instance_id"`
		Release          ReleaseInstallIdentity          `json:"release"`
		Activation       ReleaseInstallActivationRequest `json:"activation"`
	}{RequestID: req.RequestID, PluginInstanceID: req.PluginInstanceID, Release: req.Release, Activation: req.Activation}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// PrepareReleaseInstallOperation validates one request and constructs the
// canonical initial payload for a Host-owned Execution.
func PrepareReleaseInstallOperation(req StartReleaseInstallOperationRequest) (ReleaseInstallOperation, error) {
	requestSHA256, err := releaseInstallRequestSHA256(req)
	if err != nil {
		return ReleaseInstallOperation{}, err
	}
	now := normalizedOperationTime(req.Now)
	return ReleaseInstallOperation{
		Execution: execution.Execution{
			ID: req.ExecutionID, PluginInstanceID: req.PluginInstanceID, Kind: execution.KindOperation,
			Status: execution.StatusRunning, CreatedAt: now, UpdatedAt: now,
		},
		RequestID: req.RequestID, PluginInstanceID: req.PluginInstanceID,
		RequestSHA256: requestSHA256, Phase: "queued",
		Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate}, Attempt: 1,
		MutationOutcome: mutation.OutcomeNotCommitted, Release: req.Release,
		ActivationRequest: req.Activation, Activation: initialReleaseInstallActivation(req.Activation),
		PhaseDiagnostics: []ReleaseInstallPhaseDiagnostic{{
			Phase: "queued", Attempt: 1, Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate}, StartedAt: now,
		}},
	}, nil
}

func validateStartReleaseInstallOperation(req StartReleaseInstallOperationRequest) error {
	values := map[string]string{
		"request_id": req.RequestID, "execution_id": req.ExecutionID, "plugin_instance_id": req.PluginInstanceID,
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
	if !validReleaseInstallActivationRequest(req.Activation) {
		return fmt.Errorf("%w: activation request is invalid", ErrInvalidReleaseInstallOperation)
	}
	if !validCanonicalSHA256Hex(req.Release.ReleaseMetadataSHA256) {
		return fmt.Errorf("%w: release_metadata_sha256 must be a canonical sha256 digest", ErrInvalidReleaseInstallOperation)
	}
	for name, digest := range map[string]string{
		"package_sha256":  req.Release.PackageSHA256,
		"manifest_sha256": req.Release.ManifestSHA256,
		"entries_sha256":  req.Release.EntriesSHA256,
	} {
		if !validExternalPackageConfirmationDigest(digest) {
			return fmt.Errorf("%w: %s must be a canonical sha256 digest", ErrInvalidReleaseInstallOperation, name)
		}
	}
	return nil
}

func validCanonicalSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func applyReleaseInstallOperationUpdate(current ReleaseInstallOperation, req UpdateReleaseInstallOperationRequest) (ReleaseInstallOperation, error) {
	if req.ExpectedCursor != current.Execution.Cursor || strings.TrimSpace(req.ExecutionID) == "" || req.ExecutionID != current.Execution.ID {
		return ReleaseInstallOperation{}, ErrReleaseInstallOperationConflict
	}
	if !validReleaseInstallTransition(current.Execution.Status, req.Status) || strings.TrimSpace(req.Phase) == "" {
		return ReleaseInstallOperation{}, ErrInvalidReleaseInstallOperation
	}
	if !validReleaseInstallPhase(req.Phase) || req.Attempt < 1 || req.Attempt > 3 || req.RetryAfterMS < 0 || req.RetryAfterMS > 10000 {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: operation diagnostics are invalid", ErrInvalidReleaseInstallOperation)
	}
	if err := validateReleaseInstallProgress(req.Progress); err != nil {
		return ReleaseInstallOperation{}, err
	}
	if !validReleaseInstallActivation(req.Activation) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: activation result is invalid", ErrInvalidReleaseInstallOperation)
	}
	terminal := req.Status == execution.StatusCompleted || req.Status == execution.StatusFailed
	if terminal != (req.Failure != nil || req.PluginRecord != nil) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: terminal operation requires exactly one result", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == execution.StatusCompleted && (req.PluginRecord == nil || req.Failure != nil || req.MutationOutcome != mutation.OutcomeCommitted) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: successful operation requires committed plugin record", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == execution.StatusCompleted && req.Activation.Status == ReleaseInstallActivationPending {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: successful operation requires a terminal activation result", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == execution.StatusCompleted && !releaseInstallActivationMatchesRecord(req.Activation, *req.PluginRecord) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: successful operation activation does not match plugin enable state", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == execution.StatusFailed && (req.Failure == nil || req.PluginRecord != nil || strings.TrimSpace(req.Failure.Code) == "") {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: failed operation requires safe failure code", ErrInvalidReleaseInstallOperation)
	}
	now := normalizedOperationTime(req.Now)
	if now.Before(current.Execution.UpdatedAt) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: update time moved backwards", ErrInvalidReleaseInstallOperation)
	}
	current.PhaseDiagnostics = updateReleaseInstallPhaseDiagnostics(current, req, now)
	current.Phase, current.Progress = req.Phase, req.Progress
	current.Attempt, current.RetryAfterMS, current.MutationOutcome = req.Attempt, req.RetryAfterMS, req.MutationOutcome
	current.Failure, current.PluginRecord = req.Failure, req.PluginRecord
	current.Activation = req.Activation
	return current, nil
}

// ApplyReleaseInstallOperationUpdate is the canonical transition helper used
// by Host-owned durable execution stores.
func ApplyReleaseInstallOperationUpdate(current ReleaseInstallOperation, req UpdateReleaseInstallOperationRequest) (ReleaseInstallOperation, error) {
	return applyReleaseInstallOperationUpdate(current, req)
}

func updateReleaseInstallPhaseDiagnostics(current ReleaseInstallOperation, req UpdateReleaseInstallOperationRequest, now time.Time) []ReleaseInstallPhaseDiagnostic {
	diagnostics := append([]ReleaseInstallPhaseDiagnostic(nil), current.PhaseDiagnostics...)
	if len(diagnostics) == 0 {
		diagnostics = append(diagnostics, ReleaseInstallPhaseDiagnostic{
			Phase: current.Phase, Attempt: max(current.Attempt, 1), Progress: current.Progress, StartedAt: current.Execution.UpdatedAt,
		})
	}
	last := &diagnostics[len(diagnostics)-1]
	if last.Phase != req.Phase {
		completedAt := now
		last.CompletedAt = &completedAt
		last.DurationMS = max(now.Sub(last.StartedAt).Milliseconds(), 0)
		diagnostics = append(diagnostics, ReleaseInstallPhaseDiagnostic{
			Phase: req.Phase, ArtifactRole: req.ArtifactRole, Attempt: max(req.Attempt, 1),
			Progress: req.Progress, CacheHit: req.CacheHit, StartedAt: now,
		})
	} else {
		last.ArtifactRole = req.ArtifactRole
		last.Attempt = max(req.Attempt, 1)
		last.Progress = req.Progress
		last.CacheHit = last.CacheHit || req.CacheHit
	}
	if req.Status == execution.StatusCompleted || req.Status == execution.StatusFailed {
		last = &diagnostics[len(diagnostics)-1]
		completedAt := now
		last.CompletedAt = &completedAt
		last.DurationMS = max(now.Sub(last.StartedAt).Milliseconds(), 0)
	}
	return diagnostics
}

func initialReleaseInstallActivation(request ReleaseInstallActivationRequest) ReleaseInstallActivation {
	if request.Mode == ReleaseInstallActivationDisabled {
		return ReleaseInstallActivation{Status: ReleaseInstallActivationNotRequested}
	}
	return ReleaseInstallActivation{Status: ReleaseInstallActivationPending}
}

func validReleaseInstallActivationRequest(request ReleaseInstallActivationRequest) bool {
	switch request.Mode {
	case ReleaseInstallActivationAutomatic, ReleaseInstallActivationRequested:
	case ReleaseInstallActivationDisabled:
		return len(request.ApprovedPermissionIDs) == 0
	default:
		return false
	}
	previous := ""
	for _, permissionID := range request.ApprovedPermissionIDs {
		if strings.TrimSpace(permissionID) == "" || permissionID != strings.TrimSpace(permissionID) || permissionID <= previous {
			return false
		}
		previous = permissionID
	}
	return true
}

func validReleaseInstallActivation(activation ReleaseInstallActivation) bool {
	switch activation.Status {
	case ReleaseInstallActivationPending, ReleaseInstallActivationEnabled, ReleaseInstallActivationNotRequested:
		return len(activation.MissingPermissionIDs) == 0 && activation.NextAction == ""
	case ReleaseInstallActivationNeedsAttention:
		if activation.NextAction != ReleaseInstallNextActionApprovePermissions && activation.NextAction != ReleaseInstallNextActionRetryActivation {
			return false
		}
		previous := ""
		for _, permissionID := range activation.MissingPermissionIDs {
			if permissionID == "" || permissionID != strings.TrimSpace(permissionID) || permissionID <= previous {
				return false
			}
			previous = permissionID
		}
		return true
	default:
		return false
	}
}

func validReleaseInstallPhase(phase string) bool {
	switch phase {
	case "queued", "fetch_trust_evidence", "fetch_release_evidence", "download_package", "verify_hashes",
		"verify_signatures", "fetch_capability_evidence", "commit", "enable", "complete", "failed", "reconciling":
		return true
	default:
		return false
	}
}

func releaseInstallActivationMatchesRecord(activation ReleaseInstallActivation, record PluginRecord) bool {
	if activation.Status == ReleaseInstallActivationEnabled {
		return record.EnableState == EnableEnabled
	}
	return record.EnableState == EnableDisabled
}

func validReleaseInstallTransition(from, to string) bool {
	switch from {
	case execution.StatusRunning:
		return to == execution.StatusRunning || to == execution.StatusCompleted || to == execution.StatusFailed
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

func normalizedOperationTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}
