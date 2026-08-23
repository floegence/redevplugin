package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/releasecontract"
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

type ReleaseInstallStage string

const (
	ReleaseInstallStageDownload ReleaseInstallStage = "download"
	ReleaseInstallStageVerify   ReleaseInstallStage = "verify"
	ReleaseInstallStageInstall  ReleaseInstallStage = "install"
	ReleaseInstallStageEnable   ReleaseInstallStage = "enable"
)

type ReleaseInstallStageStatus string

const (
	ReleaseInstallStagePending   ReleaseInstallStageStatus = "pending"
	ReleaseInstallStageRunning   ReleaseInstallStageStatus = "running"
	ReleaseInstallStageCompleted ReleaseInstallStageStatus = "completed"
	ReleaseInstallStageFailed    ReleaseInstallStageStatus = "failed"
)

// ReleaseInstallProgressEvent is the stable user-facing projection of a
// release-install task. PhaseDiagnostics intentionally remain more detailed.
type ReleaseInstallProgressEvent struct {
	TaskID       string                    `json:"task_id"`
	RequestID    string                    `json:"request_id"`
	Stage        ReleaseInstallStage       `json:"stage"`
	Status       ReleaseInstallStageStatus `json:"status"`
	Completed    *int64                    `json:"completed,omitempty"`
	Total        *int64                    `json:"total,omitempty"`
	FailureCode  string                    `json:"failure_code,omitempty"`
	FailureStage ReleaseInstallStage       `json:"failure_stage,omitempty"`
	Retryable    *bool                     `json:"retryable,omitempty"`
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

// ReleaseInstallIdentitySHA256 returns the canonical digest of the exact
// publisher release reference consumed by an official install.
func ReleaseInstallIdentitySHA256(identity ReleaseInstallIdentity) (string, error) {
	if err := validateReleaseInstallIdentity(identity); err != nil {
		return "", err
	}
	reference := struct {
		Channel        string `json:"channel"`
		ExpectedHashes struct {
			EntriesSHA256  string `json:"entries_sha256"`
			ManifestSHA256 string `json:"manifest_sha256"`
			PackageSHA256  string `json:"package_sha256"`
		} `json:"expected_hashes"`
		PluginID              string `json:"plugin_id"`
		PublisherID           string `json:"publisher_id"`
		ReleaseMetadataRef    string `json:"release_metadata_ref"`
		ReleaseMetadataSHA256 string `json:"release_metadata_sha256"`
		SourceID              string `json:"source_id"`
		Version               string `json:"version"`
	}{
		Channel: identity.Channel, PluginID: identity.PluginID, PublisherID: identity.PublisherID,
		ReleaseMetadataRef: identity.ReleaseMetadataRef, ReleaseMetadataSHA256: identity.ReleaseMetadataSHA256,
		SourceID: identity.SourceID, Version: identity.Version,
	}
	reference.ExpectedHashes.EntriesSHA256 = identity.EntriesSHA256
	reference.ExpectedHashes.ManifestSHA256 = identity.ManifestSHA256
	reference.ExpectedHashes.PackageSHA256 = identity.PackageSHA256
	raw, err := json.Marshal(reference)
	if err != nil {
		return "", err
	}
	canonical, err := releasecontract.CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type StartReleaseInstallOperationRequest struct {
	RequestID             string                 `json:"request_id"`
	ExecutionID           string                 `json:"execution_id"`
	PluginInstanceID      string                 `json:"plugin_instance_id"`
	ReleaseIdentityDigest string                 `json:"release_identity_digest,omitempty"`
	ManifestSHA256        string                 `json:"manifest_sha256,omitempty"`
	ContractSetSHA256     string                 `json:"contract_set_sha256,omitempty"`
	SummarySHA256         string                 `json:"summary_sha256,omitempty"`
	Release               ReleaseInstallIdentity `json:"release"`
	Now                   time.Time              `json:"-"`
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
	Now             time.Time
}

type ReleaseInstallOperation struct {
	Execution             execution.Execution             `json:"-"`
	RequestID             string                          `json:"request_id"`
	PluginInstanceID      string                          `json:"plugin_instance_id"`
	ReleaseIdentityDigest string                          `json:"release_identity_digest,omitempty"`
	ManifestSHA256        string                          `json:"manifest_sha256,omitempty"`
	ContractSetSHA256     string                          `json:"contract_set_sha256,omitempty"`
	SummarySHA256         string                          `json:"summary_sha256,omitempty"`
	RequestSHA256         string                          `json:"request_sha256"`
	Phase                 string                          `json:"phase"`
	Progress              ReleaseInstallProgress          `json:"progress"`
	Attempt               int                             `json:"attempt"`
	RetryAfterMS          int64                           `json:"retry_after_ms"`
	MutationOutcome       mutation.Outcome                `json:"mutation_outcome"`
	Failure               *ReleaseInstallFailure          `json:"failure,omitempty"`
	PluginRecord          *PluginRecord                   `json:"plugin_record,omitempty"`
	PhaseDiagnostics      []ReleaseInstallPhaseDiagnostic `json:"phase_diagnostics"`
	Release               ReleaseInstallIdentity          `json:"-"`
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
		RequestID             string                 `json:"request_id"`
		PluginInstanceID      string                 `json:"plugin_instance_id"`
		ReleaseIdentityDigest string                 `json:"release_identity_digest,omitempty"`
		ManifestSHA256        string                 `json:"manifest_sha256,omitempty"`
		ContractSetSHA256     string                 `json:"contract_set_sha256,omitempty"`
		SummarySHA256         string                 `json:"summary_sha256,omitempty"`
		Release               ReleaseInstallIdentity `json:"release"`
	}{
		RequestID: req.RequestID, PluginInstanceID: req.PluginInstanceID,
		ReleaseIdentityDigest: req.ReleaseIdentityDigest, ManifestSHA256: req.ManifestSHA256,
		ContractSetSHA256: req.ContractSetSHA256, SummarySHA256: req.SummarySHA256, Release: req.Release,
	}
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
		ReleaseIdentityDigest: req.ReleaseIdentityDigest,
		ManifestSHA256:        req.ManifestSHA256, ContractSetSHA256: req.ContractSetSHA256, SummarySHA256: req.SummarySHA256,
		RequestSHA256: requestSHA256, Phase: "queued",
		Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate}, Attempt: 1,
		MutationOutcome: mutation.OutcomeNotCommitted, Release: req.Release,
		PhaseDiagnostics: []ReleaseInstallPhaseDiagnostic{{
			Phase: "queued", Attempt: 1, Progress: ReleaseInstallProgress{Kind: ReleaseInstallProgressIndeterminate}, StartedAt: now,
		}},
	}, nil
}

func validateStartReleaseInstallOperation(req StartReleaseInstallOperationRequest) error {
	values := map[string]string{
		"request_id": req.RequestID, "execution_id": req.ExecutionID, "plugin_instance_id": req.PluginInstanceID,
	}
	for name, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%w: %s is required and must be canonical", ErrInvalidReleaseInstallOperation, name)
		}
	}
	if err := validateReleaseInstallIdentity(req.Release); err != nil {
		return err
	}
	declared := map[string]string{
		"release_identity_digest": req.ReleaseIdentityDigest,
		"manifest_sha256":         req.ManifestSHA256,
		"contract_set_sha256":     req.ContractSetSHA256,
		"summary_sha256":          req.SummarySHA256,
	}
	declaredCount := 0
	for _, value := range declared {
		if value != "" {
			declaredCount++
		}
	}
	if declaredCount != len(declared) {
		return fmt.Errorf("%w: market declaration digests must be supplied together", ErrInvalidReleaseInstallOperation)
	}
	for name, digest := range declared {
		if !validExternalPackageConfirmationDigest(digest) {
			return fmt.Errorf("%w: %s must be a canonical sha256 digest", ErrInvalidReleaseInstallOperation, name)
		}
	}
	if !strings.EqualFold(strings.TrimPrefix(req.ManifestSHA256, "sha256:"), strings.TrimPrefix(req.Release.ManifestSHA256, "sha256:")) {
		return fmt.Errorf("%w: manifest_sha256 does not match release identity", ErrInvalidReleaseInstallOperation)
	}
	expectedIdentityDigest, err := ReleaseInstallIdentitySHA256(req.Release)
	if err != nil {
		return err
	}
	if req.ReleaseIdentityDigest != expectedIdentityDigest {
		return fmt.Errorf("%w: release_identity_digest does not match canonical release identity", ErrInvalidReleaseInstallOperation)
	}
	return nil
}

func validateReleaseInstallIdentity(identity ReleaseInstallIdentity) error {
	values := map[string]string{
		"source_id": identity.SourceID, "channel": identity.Channel, "release_metadata_ref": identity.ReleaseMetadataRef,
		"release_metadata_sha256": identity.ReleaseMetadataSHA256, "publisher_id": identity.PublisherID,
		"plugin_id": identity.PluginID, "version": identity.Version,
		"package_sha256": identity.PackageSHA256, "manifest_sha256": identity.ManifestSHA256,
		"entries_sha256": identity.EntriesSHA256,
	}
	for name, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%w: %s is required and must be canonical", ErrInvalidReleaseInstallOperation, name)
		}
	}
	if !validCanonicalSHA256Hex(identity.ReleaseMetadataSHA256) {
		return fmt.Errorf("%w: release_metadata_sha256 must be a canonical sha256 digest", ErrInvalidReleaseInstallOperation)
	}
	for name, digest := range map[string]string{
		"package_sha256":  identity.PackageSHA256,
		"manifest_sha256": identity.ManifestSHA256,
		"entries_sha256":  identity.EntriesSHA256,
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
	terminal := req.Status == execution.StatusCompleted || req.Status == execution.StatusFailed
	if terminal != (req.Failure != nil || req.PluginRecord != nil) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: terminal operation requires exactly one result", ErrInvalidReleaseInstallOperation)
	}
	if req.Status == execution.StatusCompleted && (req.PluginRecord == nil || req.Failure != nil || req.MutationOutcome != mutation.OutcomeCommitted || req.PluginRecord.EnableState != EnableEnabled) {
		return ReleaseInstallOperation{}, fmt.Errorf("%w: successful operation requires committed enabled plugin record", ErrInvalidReleaseInstallOperation)
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

func validReleaseInstallPhase(phase string) bool {
	switch phase {
	case "queued", "refresh_trust", "fetch_trust_evidence", "fetch_release_evidence",
		"download_package", "verify_hashes", "verify_signatures", "validate_install", "runtime_preflight",
		"fetch_capability_evidence", "commit", "complete", "reconciling":
		return true
	default:
		return false
	}
}

// ReleaseInstallStageForPhase maps internal diagnostics to the stable four
// steps rendered by host products.
func ReleaseInstallStageForPhase(phase string) ReleaseInstallStage {
	switch phase {
	case "queued", "fetch_trust_evidence", "fetch_release_evidence", "download_package":
		return ReleaseInstallStageDownload
	case "refresh_trust", "verify_hashes", "verify_signatures":
		return ReleaseInstallStageVerify
	case "validate_install", "runtime_preflight", "fetch_capability_evidence", "commit", "reconciling":
		return ReleaseInstallStageInstall
	case "complete":
		return ReleaseInstallStageEnable
	default:
		return ReleaseInstallStageInstall
	}
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
