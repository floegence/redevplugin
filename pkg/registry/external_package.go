package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/mutation"
)

type SignatureAssessmentStatus string

const (
	SignatureVerified      SignatureAssessmentStatus = "verified"
	SignatureAbsent        SignatureAssessmentStatus = "absent"
	SignatureUnknownSigner SignatureAssessmentStatus = "unknown_signer"
	SignatureInvalid       SignatureAssessmentStatus = "invalid"
	SignatureRevoked       SignatureAssessmentStatus = "revoked"
	SignatureUnavailable   SignatureAssessmentStatus = "unavailable"
)

type SignatureAssessment struct {
	Status               SignatureAssessmentStatus `json:"state"`
	Algorithm            string                    `json:"algorithm,omitempty"`
	KeyID                string                    `json:"key_id,omitempty"`
	AssessedHashes       TrustHashSet              `json:"assessed_hashes"`
	PackageSHA256        string                    `json:"package_sha256,omitempty"`
	ManifestSHA256       string                    `json:"manifest_sha256,omitempty"`
	EntriesSHA256        string                    `json:"entries_sha256,omitempty"`
	KeyringGeneration    string                    `json:"keyring_generation,omitempty"`
	RevocationGeneration string                    `json:"revocation_generation,omitempty"`
	AssessmentEpoch      string                    `json:"assessment_epoch,omitempty"`
	TrustRootEpoch       string                    `json:"trust_root_epoch,omitempty"`
	PolicyEpoch          string                    `json:"policy_epoch,omitempty"`
	RevocationEpoch      string                    `json:"revocation_epoch,omitempty"`
	ReasonCodes          []string                  `json:"reason_codes,omitempty"`
	EvidenceReference    string                    `json:"evidence_reference,omitempty"`
	AssessedAt           time.Time                 `json:"assessed_at,omitempty"`
}

type PackageSourceRedirectHop struct {
	Origin string `json:"origin"`
	Path   string `json:"path"`
}

type PackageSourceKind string

const (
	PackageSourceGitHubRepository PackageSourceKind = "github_repository"
	PackageSourcePackageURL       PackageSourceKind = "package_url"
	PackageSourceOfficialCatalog  PackageSourceKind = "official_catalog"
	PackageSourceApprovedCatalog  PackageSourceKind = "approved_catalog"
	PackageSourceLocalGenerated   PackageSourceKind = "local_generated"
	PackageSourceLegacyRegistry   PackageSourceKind = "legacy_registry"
)

type PackageSourceProvenance struct {
	Kind               PackageSourceKind          `json:"kind"`
	SourceOrigin       string                     `json:"source_origin,omitempty"`
	SourceURL          string                     `json:"source_url,omitempty"`
	FinalURL           string                     `json:"final_url,omitempty"`
	RedirectChain      []PackageSourceRedirectHop `json:"redirect_chain,omitempty"`
	RepositoryURL      string                     `json:"repository_url,omitempty"`
	GitHubRepositoryID string                     `json:"repository_id,omitempty"`
	GitHubReleaseID    string                     `json:"release_id,omitempty"`
	GitHubAssetID      string                     `json:"asset_id,omitempty"`
	GitHubOwner        string                     `json:"owner,omitempty"`
	GitHubRepository   string                     `json:"repository,omitempty"`
	ReleaseTag         string                     `json:"release_tag,omitempty"`
	AssetName          string                     `json:"asset_name,omitempty"`
	PackageSHA256      string                     `json:"package_sha256,omitempty"`
	SourceReference    string                     `json:"source_reference,omitempty"`
	SourcePath         string                     `json:"source_path,omitempty"`
	ResolvedRevision   string                     `json:"resolved_commit_sha,omitempty"`
	CatalogEntryID     string                     `json:"catalog_entry_id,omitempty"`
	RetrievedAt        time.Time                  `json:"resolved_at,omitempty"`
}

type ExecutionApprovalStatus string

const (
	ExecutionApprovalPending        ExecutionApprovalStatus = "pending"
	ExecutionApprovalUserApproved   ExecutionApprovalStatus = "user_approved"
	ExecutionApprovalPolicyApproved ExecutionApprovalStatus = "policy_approved"
	ExecutionApprovalPolicyBlocked  ExecutionApprovalStatus = "policy_blocked"
)

// ExecutionApproval is durable package authorization. Its audience is exactly
// one environment and one immutable package digest; session audiences must not
// be persisted here.
type ExecutionApproval struct {
	Status            ExecutionApprovalStatus `json:"state"`
	OwnerEnvHash      string                  `json:"owner_env_hash,omitempty"`
	PackageSHA256     string                  `json:"package_sha256,omitempty"`
	ReasonCodes       []string                `json:"reason_codes,omitempty"`
	EvidenceReference string                  `json:"evidence_reference,omitempty"`
	PolicyEpoch       string                  `json:"policy_epoch,omitempty"`
	AssessedAt        time.Time               `json:"assessed_at,omitempty"`
	ApprovedAt        time.Time               `json:"approved_at,omitempty"`
}

type UpdateEligibility string

const (
	UpdateManualOnly        UpdateEligibility = "manual_only"
	UpdateAutomaticEligible UpdateEligibility = "automatic_eligible"
)

type SecurityCapabilitySummary struct {
	SchemaVersion string   `json:"schema_version,omitempty"`
	CapabilityIDs []string `json:"capability_ids,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	CanonicalJSON string   `json:"canonical_json,omitempty"`
	Reference     string   `json:"reference,omitempty"`
	SHA256        string   `json:"sha256,omitempty"`
}

type ExternalPackageCommitIntent string

const (
	ExternalPackageInstall ExternalPackageCommitIntent = "install"
	ExternalPackageUpdate  ExternalPackageCommitIntent = "update"
)

type ExternalPackageCommitStatus string

const (
	ExternalPackageCommitting ExternalPackageCommitStatus = "committing"
	ExternalPackageCommitted  ExternalPackageCommitStatus = "committed"
)

type CommitExternalPackageRequest struct {
	InspectionID               string                      `json:"inspection_id"`
	CommitID                   string                      `json:"commit_id"`
	Intent                     ExternalPackageCommitIntent `json:"intent"`
	ConfirmationDigest         string                      `json:"confirmation_digest"`
	ExpectedManagementRevision uint64                      `json:"expected_management_revision"`
	IntendedFingerprint        string                      `json:"intended_fingerprint"`
	IntendedPackageSHA256      string                      `json:"intended_package_sha256"`
	Record                     PluginRecord                `json:"record"`
	Now                        time.Time                   `json:"-"`
}

type QueryExternalPackageCommitRequest struct {
	InspectionID string `json:"inspection_id"`
	CommitID     string `json:"commit_id,omitempty"`
}

type ExternalPackageCommitResult struct {
	InspectionID    string                      `json:"inspection_id"`
	CommitID        string                      `json:"commit_id"`
	Intent          ExternalPackageCommitIntent `json:"intent"`
	Status          ExternalPackageCommitStatus `json:"status"`
	MutationOutcome mutation.Outcome            `json:"mutation_outcome"`
	RecordSnapshot  *PluginRecord               `json:"record_snapshot,omitempty"`
	FailureCode     string                      `json:"failure_code,omitempty"`
	CreatedAt       time.Time                   `json:"created_at"`
	UpdatedAt       time.Time                   `json:"updated_at"`
}

type ExternalPackageStore interface {
	CommitExternalPackage(context.Context, CommitExternalPackageRequest) (ExternalPackageCommitResult, error)
	QueryExternalPackageCommit(context.Context, QueryExternalPackageCommitRequest) (ExternalPackageCommitResult, error)
}

var (
	ErrExternalPackageCommitNotFound = errors.New("external package commit not found")
	ErrExternalPackageCommitConflict = errors.New("external package commit identity conflict")
	ErrInvalidExternalPackageCommit  = errors.New("invalid external package commit")
)

type externalPackageCommitReceipt struct {
	OwnerEnvHash  string
	RequestSHA256 string
	Request       CommitExternalPackageRequest
	Result        ExternalPackageCommitResult
}

func (s *MemoryStore) CommitExternalPackage(ctx context.Context, req CommitExternalPackageRequest) (ExternalPackageCommitResult, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if err := validateExternalPackageCommit(ownerEnvHash, req); err != nil {
		return ExternalPackageCommitResult{}, err
	}
	requestSHA256, err := externalPackageRequestSHA256(req)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := externalPackageCommitKey(ownerEnvHash, req.InspectionID)
	if receipt, ok := s.externalPackageCommits[key]; ok {
		if receipt.RequestSHA256 != requestSHA256 {
			return ExternalPackageCommitResult{}, ErrExternalPackageCommitConflict
		}
		return cloneExternalPackageCommitResult(receipt.Result)
	}
	for _, receipt := range s.externalPackageCommits {
		if receipt.OwnerEnvHash == ownerEnvHash && receipt.Request.CommitID == req.CommitID {
			return ExternalPackageCommitResult{}, ErrExternalPackageCommitConflict
		}
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := ExternalPackageCommitResult{
		InspectionID:    req.InspectionID,
		CommitID:        req.CommitID,
		Intent:          req.Intent,
		Status:          ExternalPackageCommitting,
		MutationOutcome: mutation.OutcomeUnknown,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	s.externalPackageCommits[key] = externalPackageCommitReceipt{OwnerEnvHash: ownerEnvHash, RequestSHA256: requestSHA256, Request: req, Result: result}

	recordKey := environmentRecordKey(ownerEnvHash, req.Record.PluginInstanceID)
	existing, exists := s.records[recordKey]
	record, err := prepareExternalPackageRecord(ownerEnvHash, req, existing, exists, now)
	if err != nil {
		delete(s.externalPackageCommits, key)
		return ExternalPackageCommitResult{}, err
	}
	s.records[recordKey] = record
	snapshot, err := clonePluginRecord(record)
	if err != nil {
		delete(s.records, recordKey)
		delete(s.externalPackageCommits, key)
		return ExternalPackageCommitResult{}, err
	}
	result.Status = ExternalPackageCommitted
	result.MutationOutcome = mutation.OutcomeCommitted
	result.RecordSnapshot = &snapshot
	result.UpdatedAt = now
	s.externalPackageCommits[key] = externalPackageCommitReceipt{OwnerEnvHash: ownerEnvHash, RequestSHA256: requestSHA256, Request: req, Result: result}
	return cloneExternalPackageCommitResult(result)
}

func (s *MemoryStore) QueryExternalPackageCommit(ctx context.Context, req QueryExternalPackageCommitRequest) (ExternalPackageCommitResult, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	if strings.TrimSpace(req.InspectionID) == "" {
		return ExternalPackageCommitResult{}, fmt.Errorf("%w: inspection_id is required", ErrInvalidExternalPackageCommit)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	receipt, ok := s.externalPackageCommits[externalPackageCommitKey(ownerEnvHash, req.InspectionID)]
	if !ok {
		return ExternalPackageCommitResult{}, ErrExternalPackageCommitNotFound
	}
	if req.CommitID != "" && req.CommitID != receipt.Request.CommitID {
		return ExternalPackageCommitResult{}, ErrExternalPackageCommitNotFound
	}
	return cloneExternalPackageCommitResult(receipt.Result)
}

func validateExternalPackageCommit(ownerEnvHash string, req CommitExternalPackageRequest) error {
	for name, value := range map[string]string{
		"inspection_id":           req.InspectionID,
		"commit_id":               req.CommitID,
		"confirmation_digest":     req.ConfirmationDigest,
		"intended_fingerprint":    req.IntendedFingerprint,
		"intended_package_sha256": req.IntendedPackageSHA256,
		"plugin_instance_id":      req.Record.PluginInstanceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidExternalPackageCommit, name)
		}
	}
	if req.Intent != ExternalPackageInstall && req.Intent != ExternalPackageUpdate {
		return fmt.Errorf("%w: unsupported intent %q", ErrInvalidExternalPackageCommit, req.Intent)
	}
	if req.Intent == ExternalPackageInstall && req.ExpectedManagementRevision != 0 {
		return fmt.Errorf("%w: install expected_management_revision must be zero", ErrInvalidExternalPackageCommit)
	}
	if req.Intent == ExternalPackageUpdate && req.ExpectedManagementRevision == 0 {
		return fmt.Errorf("%w: update expected_management_revision is required", ErrInvalidExternalPackageCommit)
	}
	if req.Record.OwnerEnvHash != "" && req.Record.OwnerEnvHash != ownerEnvHash {
		return ErrOwnerScopeMismatch
	}
	if req.Record.ActiveFingerprint != req.IntendedFingerprint || req.Record.PackageHash != req.IntendedPackageSHA256 {
		return fmt.Errorf("%w: intended package identity does not match record", ErrInvalidExternalPackageCommit)
	}
	if req.Record.ManifestHash == "" || req.Record.EntriesHash == "" {
		return fmt.Errorf("%w: intended manifest and entries hashes are required", ErrInvalidExternalPackageCommit)
	}
	if !validExternalPackageConfirmationDigest(req.ConfirmationDigest) {
		return fmt.Errorf("%w: confirmation_digest must be a canonical sha256 digest", ErrInvalidExternalPackageCommit)
	}
	approval := req.Record.ExecutionApproval
	if !validExecutionApprovalStatus(approval.Status) || approval.OwnerEnvHash != ownerEnvHash || approval.PackageSHA256 != req.IntendedPackageSHA256 {
		return fmt.Errorf("%w: execution approval must bind owner_env_hash and intended package hash", ErrInvalidExternalPackageCommit)
	}
	if approval.Status != ExecutionApprovalUserApproved && approval.Status != ExecutionApprovalPolicyApproved {
		return fmt.Errorf("%w: a committed package requires an approved execution decision", ErrInvalidExternalPackageCommit)
	}
	if !validSignatureAssessmentStatus(req.Record.SignatureAssessment.Status) || !validPackageSourceKind(req.Record.PackageSourceProvenance.Kind) || !validUpdateEligibility(req.Record.UpdateEligibility) {
		return fmt.Errorf("%w: package security facts are incomplete", ErrInvalidExternalPackageCommit)
	}
	if req.Record.SignatureAssessment.Status == SignatureInvalid || req.Record.SignatureAssessment.Status == SignatureRevoked {
		return fmt.Errorf("%w: invalid or revoked signatures cannot be committed", ErrInvalidExternalPackageCommit)
	}
	if req.Record.SignatureAssessment.Status == SignatureVerified && (strings.TrimSpace(req.Record.SignatureAssessment.Algorithm) == "" || strings.TrimSpace(req.Record.SignatureAssessment.KeyID) == "") {
		return fmt.Errorf("%w: verified signatures require algorithm and key identity", ErrInvalidExternalPackageCommit)
	}
	for name, actual := range map[string]string{
		"signature package": req.Record.SignatureAssessment.PackageSHA256,
		"assessed package":  req.Record.SignatureAssessment.AssessedHashes.PackageSHA256,
		"source package":    req.Record.PackageSourceProvenance.PackageSHA256,
	} {
		if actual != req.Record.PackageHash {
			return fmt.Errorf("%w: %s hash does not match intended package", ErrInvalidExternalPackageCommit, name)
		}
	}
	for name, actual := range map[string]string{
		"signature manifest": req.Record.SignatureAssessment.ManifestSHA256,
		"assessed manifest":  req.Record.SignatureAssessment.AssessedHashes.ManifestSHA256,
	} {
		if actual != req.Record.ManifestHash {
			return fmt.Errorf("%w: %s hash does not match intended manifest", ErrInvalidExternalPackageCommit, name)
		}
	}
	for name, actual := range map[string]string{
		"signature entries": req.Record.SignatureAssessment.EntriesSHA256,
		"assessed entries":  req.Record.SignatureAssessment.AssessedHashes.EntriesSHA256,
	} {
		if actual != req.Record.EntriesHash {
			return fmt.Errorf("%w: %s hash does not match intended entries", ErrInvalidExternalPackageCommit, name)
		}
	}
	if req.Record.SignatureAssessment.Status != SignatureVerified && req.Record.UpdateEligibility != UpdateManualOnly {
		return fmt.Errorf("%w: unverified packages must use manual_only updates", ErrInvalidExternalPackageCommit)
	}
	return nil
}

func validSignatureAssessmentStatus(status SignatureAssessmentStatus) bool {
	switch status {
	case SignatureVerified, SignatureAbsent, SignatureUnknownSigner, SignatureInvalid, SignatureRevoked, SignatureUnavailable:
		return true
	default:
		return false
	}
}

func validPackageSourceKind(kind PackageSourceKind) bool {
	switch kind {
	case PackageSourceGitHubRepository, PackageSourcePackageURL, PackageSourceOfficialCatalog,
		PackageSourceApprovedCatalog, PackageSourceLocalGenerated, PackageSourceLegacyRegistry:
		return true
	default:
		return false
	}
}

func validExecutionApprovalStatus(status ExecutionApprovalStatus) bool {
	switch status {
	case ExecutionApprovalPending, ExecutionApprovalUserApproved, ExecutionApprovalPolicyApproved, ExecutionApprovalPolicyBlocked:
		return true
	default:
		return false
	}
}

func validUpdateEligibility(eligibility UpdateEligibility) bool {
	return eligibility == UpdateManualOnly || eligibility == UpdateAutomaticEligible
}

func validExternalPackageConfirmationDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	digest := value[len(prefix):]
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(digest) == digest
}

func validatePersistedPluginSecurityFacts(record PluginRecord) error {
	if !validSignatureAssessmentStatus(record.SignatureAssessment.Status) {
		return fmt.Errorf("plugin %q has invalid signature assessment status %q", record.PluginInstanceID, record.SignatureAssessment.Status)
	}
	if !validPackageSourceKind(record.PackageSourceProvenance.Kind) {
		return fmt.Errorf("plugin %q has invalid package source kind %q", record.PluginInstanceID, record.PackageSourceProvenance.Kind)
	}
	if !validExecutionApprovalStatus(record.ExecutionApproval.Status) {
		return fmt.Errorf("plugin %q has invalid execution approval status %q", record.PluginInstanceID, record.ExecutionApproval.Status)
	}
	if !validUpdateEligibility(record.UpdateEligibility) {
		return fmt.Errorf("plugin %q has invalid update eligibility %q", record.PluginInstanceID, record.UpdateEligibility)
	}
	if record.ExecutionApproval.OwnerEnvHash != record.OwnerEnvHash || record.ExecutionApproval.PackageSHA256 != record.PackageHash {
		return fmt.Errorf("plugin %q execution approval is not bound to its owner and package", record.PluginInstanceID)
	}
	if record.SignatureAssessment.PackageSHA256 != record.PackageHash ||
		record.SignatureAssessment.ManifestSHA256 != record.ManifestHash ||
		record.SignatureAssessment.EntriesSHA256 != record.EntriesHash ||
		record.SignatureAssessment.AssessedHashes.PackageSHA256 != record.PackageHash ||
		record.SignatureAssessment.AssessedHashes.ManifestSHA256 != record.ManifestHash ||
		record.SignatureAssessment.AssessedHashes.EntriesSHA256 != record.EntriesHash {
		return fmt.Errorf("plugin %q signature assessment hashes do not match the stored package", record.PluginInstanceID)
	}
	if record.PackageSourceProvenance.PackageSHA256 != record.PackageHash {
		return fmt.Errorf("plugin %q source provenance is not bound to the stored package", record.PluginInstanceID)
	}
	if record.SignatureAssessment.Status == SignatureVerified &&
		(strings.TrimSpace(record.SignatureAssessment.Algorithm) == "" || strings.TrimSpace(record.SignatureAssessment.KeyID) == "") {
		return fmt.Errorf("plugin %q verified signature is missing algorithm or key identity", record.PluginInstanceID)
	}
	if (record.SignatureAssessment.Status == SignatureInvalid || record.SignatureAssessment.Status == SignatureRevoked) && record.ExecutionApproval.Status != ExecutionApprovalPolicyBlocked {
		return fmt.Errorf("plugin %q invalid or revoked signature is not policy blocked", record.PluginInstanceID)
	}
	if record.SignatureAssessment.Status != SignatureVerified && record.UpdateEligibility != UpdateManualOnly {
		return fmt.Errorf("plugin %q unverified package is eligible for automatic updates", record.PluginInstanceID)
	}
	for index, version := range record.VersionHistory {
		carrier := PluginRecord{
			OwnerEnvHash: record.OwnerEnvHash, PluginInstanceID: fmt.Sprintf("%s version[%d]", record.PluginInstanceID, index),
			PackageHash: version.PackageHash, ManifestHash: version.ManifestHash, EntriesHash: version.EntriesHash,
			SignatureAssessment: version.SignatureAssessment, PackageSourceProvenance: version.PackageSourceProvenance,
			ExecutionApproval: version.ExecutionApproval, UpdateEligibility: version.UpdateEligibility,
		}
		if err := validatePersistedPluginSecurityFactsWithoutHistory(carrier); err != nil {
			return err
		}
	}
	return nil
}

func validatePersistedPluginSecurityFactsWithoutHistory(record PluginRecord) error {
	history := record.VersionHistory
	record.VersionHistory = nil
	err := validatePersistedPluginSecurityFacts(record)
	record.VersionHistory = history
	return err
}

func validatePersistedExternalPackageReceipt(receipt externalPackageCommitReceipt) error {
	req := receipt.Request
	result := receipt.Result
	for name, value := range map[string]string{
		"owner_env_hash": receipt.OwnerEnvHash, "inspection_id": req.InspectionID,
		"commit_id": req.CommitID, "confirmation_digest": req.ConfirmationDigest,
		"intended_fingerprint": req.IntendedFingerprint, "intended_package_sha256": req.IntendedPackageSHA256,
		"plugin_instance_id": req.Record.PluginInstanceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("external package receipt has an empty %s", name)
		}
	}
	requestDigest, err := hex.DecodeString(receipt.RequestSHA256)
	if err != nil || len(requestDigest) != sha256.Size || strings.ToLower(receipt.RequestSHA256) != receipt.RequestSHA256 {
		return fmt.Errorf("external package receipt %q has an invalid request digest", req.InspectionID)
	}
	if !validExternalPackageConfirmationDigest(req.ConfirmationDigest) {
		return fmt.Errorf("external package receipt %q has an invalid confirmation digest", req.InspectionID)
	}
	if req.Intent != ExternalPackageInstall && req.Intent != ExternalPackageUpdate {
		return fmt.Errorf("external package receipt %q has invalid intent %q", req.InspectionID, req.Intent)
	}
	if (req.Intent == ExternalPackageInstall && req.ExpectedManagementRevision != 0) ||
		(req.Intent == ExternalPackageUpdate && req.ExpectedManagementRevision == 0) {
		return fmt.Errorf("external package receipt %q has an invalid expected management revision", req.InspectionID)
	}
	if result.InspectionID != req.InspectionID || result.CommitID != req.CommitID || result.Intent != req.Intent {
		return fmt.Errorf("external package receipt %q result identity does not match its request", req.InspectionID)
	}
	if result.CreatedAt.UnixNano() <= 0 || result.UpdatedAt.Before(result.CreatedAt) || strings.TrimSpace(result.FailureCode) != "" {
		return fmt.Errorf("external package receipt %q has invalid lifecycle metadata", req.InspectionID)
	}
	switch result.Status {
	case ExternalPackageCommitting:
		if result.MutationOutcome != mutation.OutcomeUnknown || result.RecordSnapshot != nil {
			return fmt.Errorf("external package receipt %q has inconsistent committing state", req.InspectionID)
		}
	case ExternalPackageCommitted:
		if result.MutationOutcome != mutation.OutcomeCommitted || result.RecordSnapshot == nil {
			return fmt.Errorf("external package receipt %q has inconsistent committed state", req.InspectionID)
		}
		snapshot := *result.RecordSnapshot
		if !snapshot.UpdatedAt.Equal(result.UpdatedAt) {
			return fmt.Errorf("external package receipt %q snapshot update time does not match the receipt", req.InspectionID)
		}
		if snapshot.OwnerEnvHash != receipt.OwnerEnvHash || snapshot.PluginInstanceID != req.Record.PluginInstanceID ||
			snapshot.ActiveFingerprint != req.IntendedFingerprint || snapshot.PackageHash != req.IntendedPackageSHA256 {
			return fmt.Errorf("external package receipt %q snapshot identity does not match its request", req.InspectionID)
		}
		if req.Intent == ExternalPackageInstall && snapshot.ManagementRevision != 1 {
			return fmt.Errorf("external package receipt %q install snapshot has an invalid management revision", req.InspectionID)
		}
		if req.Intent == ExternalPackageUpdate && snapshot.ManagementRevision != req.ExpectedManagementRevision+1 {
			return fmt.Errorf("external package receipt %q update snapshot has an invalid management revision", req.InspectionID)
		}
		if snapshot.ExecutionApproval.Status != ExecutionApprovalUserApproved && snapshot.ExecutionApproval.Status != ExecutionApprovalPolicyApproved {
			return fmt.Errorf("external package receipt %q snapshot is not execution approved", req.InspectionID)
		}
		if err := validatePersistedPluginSecurityFacts(snapshot); err != nil {
			return fmt.Errorf("external package receipt %q snapshot: %w", req.InspectionID, err)
		}
	default:
		return fmt.Errorf("external package receipt %q has invalid status %q", req.InspectionID, result.Status)
	}
	return nil
}

func prepareExternalPackageRecord(ownerEnvHash string, req CommitExternalPackageRequest, existing PluginRecord, exists bool, now time.Time) (PluginRecord, error) {
	record := req.Record
	record.OwnerEnvHash = ownerEnvHash
	if req.Intent == ExternalPackageInstall {
		if exists && existing.DeletedAt == nil {
			return PluginRecord{}, &ManagementRevisionConflictError{PluginInstanceID: record.PluginInstanceID, Expected: 0, Actual: existing.ManagementRevision}
		}
		record.InstalledAt = now
		if record.PolicyRevision == 0 {
			record.PolicyRevision = 1
		}
		record.ManagementRevision = 1
	} else {
		if !exists || existing.DeletedAt != nil {
			return PluginRecord{}, ErrNotFound
		}
		if existing.ManagementRevision != req.ExpectedManagementRevision {
			return PluginRecord{}, &ManagementRevisionConflictError{PluginInstanceID: record.PluginInstanceID, Expected: req.ExpectedManagementRevision, Actual: existing.ManagementRevision}
		}
		record.InstalledAt = existing.InstalledAt
		record.ManagementRevision = existing.ManagementRevision + 1
		record.PolicyRevision = existing.PolicyRevision
		record.RevokeEpoch = existing.RevokeEpoch + 1
	}
	record.UpdatedAt = now
	record = normalizePluginSecurityFacts(record)
	if err := validatePersistedPluginSecurityFacts(record); err != nil {
		return PluginRecord{}, err
	}
	return clonePluginRecord(record)
}

func externalPackageRequestSHA256(req CommitExternalPackageRequest) (string, error) {
	req.Now = time.Time{}
	req.Record.OwnerEnvHash = ""
	raw, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func cloneExternalPackageCommitResult(result ExternalPackageCommitResult) (ExternalPackageCommitResult, error) {
	if result.RecordSnapshot == nil {
		return result, nil
	}
	snapshot, err := clonePluginRecord(*result.RecordSnapshot)
	if err != nil {
		return ExternalPackageCommitResult{}, err
	}
	result.RecordSnapshot = &snapshot
	return result, nil
}

func externalPackageCommitKey(ownerEnvHash, inspectionID string) string {
	return strings.TrimSpace(ownerEnvHash) + "\x00" + strings.TrimSpace(inspectionID)
}

func normalizePluginSecurityFacts(record PluginRecord) PluginRecord {
	record = normalizeTrustAssessment(record)
	if record.SignatureAssessment.Status == "" {
		switch record.TrustState {
		case TrustVerified:
			record.SignatureAssessment.Status = SignatureUnavailable
			if record.TrustAssessment.VerifiedSignature != nil &&
				strings.TrimSpace(record.TrustAssessment.VerifiedSignature.Algorithm) != "" &&
				strings.TrimSpace(record.TrustAssessment.VerifiedSignature.KeyID) != "" {
				record.SignatureAssessment.Status = SignatureVerified
				record.SignatureAssessment.Algorithm = record.TrustAssessment.VerifiedSignature.Algorithm
				record.SignatureAssessment.KeyID = record.TrustAssessment.VerifiedSignature.KeyID
			}
		case TrustUnsignedLocal:
			record.SignatureAssessment.Status = SignatureAbsent
		default:
			record.SignatureAssessment.Status = SignatureUnavailable
		}
	}
	if record.SignatureAssessment.PackageSHA256 == "" {
		record.SignatureAssessment.PackageSHA256 = record.SignatureAssessment.AssessedHashes.PackageSHA256
		if record.SignatureAssessment.PackageSHA256 == "" {
			record.SignatureAssessment.PackageSHA256 = record.PackageHash
		}
	}
	if record.SignatureAssessment.ManifestSHA256 == "" {
		record.SignatureAssessment.ManifestSHA256 = record.SignatureAssessment.AssessedHashes.ManifestSHA256
		if record.SignatureAssessment.ManifestSHA256 == "" {
			record.SignatureAssessment.ManifestSHA256 = record.ManifestHash
		}
	}
	if record.SignatureAssessment.EntriesSHA256 == "" {
		record.SignatureAssessment.EntriesSHA256 = record.SignatureAssessment.AssessedHashes.EntriesSHA256
		if record.SignatureAssessment.EntriesSHA256 == "" {
			record.SignatureAssessment.EntriesSHA256 = record.EntriesHash
		}
	}
	record.SignatureAssessment.AssessedHashes = TrustHashSet{
		PackageSHA256:  record.SignatureAssessment.PackageSHA256,
		ManifestSHA256: record.SignatureAssessment.ManifestSHA256,
		EntriesSHA256:  record.SignatureAssessment.EntriesSHA256,
	}
	if record.SignatureAssessment.PolicyEpoch == "" {
		record.SignatureAssessment.PolicyEpoch = record.TrustAssessment.PolicyEpoch
	}
	if record.SignatureAssessment.RevocationEpoch == "" {
		record.SignatureAssessment.RevocationEpoch = record.TrustAssessment.RevocationEpoch
	}
	if record.PackageSourceProvenance.Kind == "" {
		if record.TrustState == TrustUnsignedLocal {
			record.PackageSourceProvenance.Kind = PackageSourceLocalGenerated
		} else {
			record.PackageSourceProvenance.Kind = PackageSourceLegacyRegistry
		}
	}
	if record.PackageSourceProvenance.PackageSHA256 == "" {
		record.PackageSourceProvenance.PackageSHA256 = record.PackageHash
	}
	if record.ExecutionApproval.Status == "" {
		record.ExecutionApproval.Status = ExecutionApprovalPending
		if record.TrustState == TrustBlockedSecurity {
			record.ExecutionApproval.Status = ExecutionApprovalPolicyBlocked
		} else if record.TrustState == TrustVerified && record.EnableState == EnableEnabled {
			record.ExecutionApproval.Status = ExecutionApprovalPolicyApproved
		}
		record.ExecutionApproval.OwnerEnvHash = record.OwnerEnvHash
		record.ExecutionApproval.PackageSHA256 = record.PackageHash
	}
	if record.UpdateEligibility == "" {
		record.UpdateEligibility = UpdateManualOnly
	}
	for index := range record.VersionHistory {
		version := record.VersionHistory[index]
		carrier := PluginRecord{
			OwnerEnvHash:            record.OwnerEnvHash,
			PackageHash:             version.PackageHash,
			ManifestHash:            version.ManifestHash,
			EntriesHash:             version.EntriesHash,
			TrustState:              version.TrustState,
			TrustAssessment:         version.TrustAssessment,
			SignatureAssessment:     version.SignatureAssessment,
			PackageSourceProvenance: version.PackageSourceProvenance,
			ExecutionApproval:       version.ExecutionApproval,
			UpdateEligibility:       version.UpdateEligibility,
			EnableState:             EnableDisabled,
		}
		carrier = normalizePluginSecurityFactsWithoutHistory(carrier)
		version.TrustState = carrier.TrustState
		version.TrustAssessment = carrier.TrustAssessment
		version.SignatureAssessment = carrier.SignatureAssessment
		version.PackageSourceProvenance = carrier.PackageSourceProvenance
		version.ExecutionApproval = carrier.ExecutionApproval
		version.UpdateEligibility = carrier.UpdateEligibility
		record.VersionHistory[index] = version
	}
	return record
}

func normalizePluginSecurityFactsWithoutHistory(record PluginRecord) PluginRecord {
	history := record.VersionHistory
	record.VersionHistory = nil
	record = normalizePluginSecurityFacts(record)
	record.VersionHistory = history
	return record
}
