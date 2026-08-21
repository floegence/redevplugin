package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
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
	PackageSourcePackageUpload    PackageSourceKind = "package_upload"
	PackageSourceOfficialCatalog  PackageSourceKind = "official_catalog"
	PackageSourceApprovedCatalog  PackageSourceKind = "approved_catalog"
	PackageSourceLocalGenerated   PackageSourceKind = "local_generated"
)

type PackageSourceProvenance struct {
	Kind               PackageSourceKind          `json:"kind"`
	UploadID           string                     `json:"upload_id,omitempty"`
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

type ExternalPackageInstallIntent string

const (
	ExternalPackageInstall ExternalPackageInstallIntent = "install"
	ExternalPackageUpdate  ExternalPackageInstallIntent = "update"
)

type InstallExternalPackageRequest struct {
	Intent                     ExternalPackageInstallIntent `json:"intent"`
	ExpectedManagementRevision uint64                       `json:"expected_management_revision"`
	Record                     PluginRecord                 `json:"record"`
	Now                        time.Time                    `json:"-"`
}

var ErrInvalidExternalPackageInstall = errors.New("invalid external package install")

// PrepareExternalPackageInstall applies the canonical external-package
// validation, owner binding, revision transition, and security normalization
// without persisting state. Persistent authorities use this function inside
// their own atomic transaction so Host has one installation state machine.
func PrepareExternalPackageInstall(ownerEnvHash string, req InstallExternalPackageRequest, existing *PluginRecord) (PluginRecord, error) {
	if err := validateExternalPackageInstall(ownerEnvHash, req); err != nil {
		return PluginRecord{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var current PluginRecord
	exists := existing != nil
	if exists {
		current = *existing
	}
	return prepareExternalPackageRecord(ownerEnvHash, req, current, exists, now)
}

func validateExternalPackageInstall(ownerEnvHash string, req InstallExternalPackageRequest) error {
	for name, value := range map[string]string{
		"active_fingerprint": req.Record.ActiveFingerprint,
		"package_sha256":     req.Record.PackageHash,
		"plugin_instance_id": req.Record.PluginInstanceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidExternalPackageInstall, name)
		}
	}
	if req.Intent != ExternalPackageInstall && req.Intent != ExternalPackageUpdate {
		return fmt.Errorf("%w: unsupported intent %q", ErrInvalidExternalPackageInstall, req.Intent)
	}
	if req.Intent == ExternalPackageInstall && req.ExpectedManagementRevision != 0 {
		return fmt.Errorf("%w: install expected_management_revision must be zero", ErrInvalidExternalPackageInstall)
	}
	if req.Intent == ExternalPackageUpdate && req.ExpectedManagementRevision == 0 {
		return fmt.Errorf("%w: update expected_management_revision is required", ErrInvalidExternalPackageInstall)
	}
	if req.Record.OwnerEnvHash != "" && req.Record.OwnerEnvHash != ownerEnvHash {
		return ErrOwnerScopeMismatch
	}
	if req.Record.ManifestHash == "" || req.Record.EntriesHash == "" {
		return fmt.Errorf("%w: intended manifest and entries hashes are required", ErrInvalidExternalPackageInstall)
	}
	approval := req.Record.ExecutionApproval
	if !validExecutionApprovalStatus(approval.Status) || approval.OwnerEnvHash != ownerEnvHash || approval.PackageSHA256 != req.Record.PackageHash {
		return fmt.Errorf("%w: execution approval must bind owner_env_hash and intended package hash", ErrInvalidExternalPackageInstall)
	}
	if approval.Status != ExecutionApprovalUserApproved && approval.Status != ExecutionApprovalPolicyApproved {
		return fmt.Errorf("%w: an installed package requires an approved execution decision", ErrInvalidExternalPackageInstall)
	}
	if !validSignatureAssessmentStatus(req.Record.SignatureAssessment.Status) || !validPackageSourceProvenance(req.Record.PackageSourceProvenance) || !validUpdateEligibility(req.Record.UpdateEligibility) {
		return fmt.Errorf("%w: package security facts are incomplete", ErrInvalidExternalPackageInstall)
	}
	if req.Record.SignatureAssessment.Status == SignatureInvalid || req.Record.SignatureAssessment.Status == SignatureRevoked {
		return fmt.Errorf("%w: invalid or revoked signatures cannot be installed", ErrInvalidExternalPackageInstall)
	}
	if req.Record.SignatureAssessment.Status == SignatureVerified && (strings.TrimSpace(req.Record.SignatureAssessment.Algorithm) == "" || strings.TrimSpace(req.Record.SignatureAssessment.KeyID) == "") {
		return fmt.Errorf("%w: verified signatures require algorithm and key identity", ErrInvalidExternalPackageInstall)
	}
	for name, actual := range map[string]string{
		"signature package": req.Record.SignatureAssessment.PackageSHA256,
		"assessed package":  req.Record.SignatureAssessment.AssessedHashes.PackageSHA256,
		"source package":    req.Record.PackageSourceProvenance.PackageSHA256,
	} {
		if actual != req.Record.PackageHash {
			return fmt.Errorf("%w: %s hash does not match intended package", ErrInvalidExternalPackageInstall, name)
		}
	}
	for name, actual := range map[string]string{
		"signature manifest": req.Record.SignatureAssessment.ManifestSHA256,
		"assessed manifest":  req.Record.SignatureAssessment.AssessedHashes.ManifestSHA256,
	} {
		if actual != req.Record.ManifestHash {
			return fmt.Errorf("%w: %s hash does not match intended manifest", ErrInvalidExternalPackageInstall, name)
		}
	}
	for name, actual := range map[string]string{
		"signature entries": req.Record.SignatureAssessment.EntriesSHA256,
		"assessed entries":  req.Record.SignatureAssessment.AssessedHashes.EntriesSHA256,
	} {
		if actual != req.Record.EntriesHash {
			return fmt.Errorf("%w: %s hash does not match intended entries", ErrInvalidExternalPackageInstall, name)
		}
	}
	if req.Record.SignatureAssessment.Status != SignatureVerified && req.Record.UpdateEligibility != UpdateManualOnly {
		return fmt.Errorf("%w: unverified packages must use manual_only updates", ErrInvalidExternalPackageInstall)
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
	case PackageSourceGitHubRepository, PackageSourcePackageURL, PackageSourcePackageUpload, PackageSourceOfficialCatalog,
		PackageSourceApprovedCatalog, PackageSourceLocalGenerated:
		return true
	default:
		return false
	}
}

func validPackageSourceProvenance(value PackageSourceProvenance) bool {
	if !validPackageSourceKind(value.Kind) {
		return false
	}
	if value.Kind != PackageSourcePackageUpload {
		return value.UploadID == ""
	}
	const prefix = "upload_"
	if !strings.HasPrefix(value.UploadID, prefix) || len(value.UploadID) != len(prefix)+32 {
		return false
	}
	decoded, err := hex.DecodeString(value.UploadID[len(prefix):])
	return err == nil && len(decoded) == 16 && strings.ToLower(value.UploadID) == value.UploadID &&
		strings.TrimSpace(value.PackageSHA256) != "" && value.RetrievedAt.UnixNano() > 0 &&
		value.SourceOrigin == "" && value.SourceURL == "" && value.FinalURL == "" && len(value.RedirectChain) == 0 &&
		value.RepositoryURL == "" && value.GitHubRepositoryID == "" && value.GitHubReleaseID == "" &&
		value.GitHubAssetID == "" && value.GitHubOwner == "" && value.GitHubRepository == "" &&
		value.ReleaseTag == "" && value.AssetName == "" && value.SourceReference == "" && value.SourcePath == "" &&
		value.ResolvedRevision == "" && value.CatalogEntryID == ""
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
	if !validPackageSourceProvenance(record.PackageSourceProvenance) {
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
			OwnerEnvHash: record.OwnerEnvHash, PluginInstanceID: record.PluginInstanceID,
			PublisherID: version.Manifest.Publisher.PublisherID, PluginID: version.Manifest.PluginID(), Version: version.Version,
			ActiveFingerprint: version.ActiveFingerprint,
			PackageHash:       version.PackageHash, ManifestHash: version.ManifestHash, EntriesHash: version.EntriesHash,
			SignatureAssessment: version.SignatureAssessment, PackageSourceProvenance: version.PackageSourceProvenance,
			ExecutionApproval: version.ExecutionApproval, UpdateEligibility: version.UpdateEligibility,
			ReleaseTrustBinding: version.ReleaseTrustBinding,
		}
		if err := validatePersistedPluginSecurityFactsWithoutHistory(carrier); err != nil {
			return fmt.Errorf("plugin %q version[%d] has invalid security facts: %w", record.PluginInstanceID, index, err)
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

func prepareExternalPackageRecord(ownerEnvHash string, req InstallExternalPackageRequest, existing PluginRecord, exists bool, now time.Time) (PluginRecord, error) {
	record := req.Record
	record.OwnerEnvHash = ownerEnvHash
	if req.Intent == ExternalPackageInstall {
		if exists && existing.DeletedAt == nil {
			return PluginRecord{}, &ManagementRevisionConflictError{PluginInstanceID: record.PluginInstanceID, Expected: 0, Actual: existing.ManagementRevision}
		}
		// RevokeEpoch is an instance-scoped monotonic credential floor. A fresh
		// external package starts at one; reinstalling a deleted stable instance
		// inherits its tombstone floor so new credentials remain usable without
		// reviving credentials revoked by uninstall.
		record.RevokeEpoch = 1
		if exists && existing.RevokeEpoch > record.RevokeEpoch {
			record.RevokeEpoch = existing.RevokeEpoch
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

func approveExplicitLocalImport(record PluginRecord) PluginRecord {
	provenance := record.LocalImportProvenance
	if record.EnableState != EnableEnabled || record.TrustState != TrustUnsignedLocal ||
		record.ExecutionApproval.Status != ExecutionApprovalPending ||
		record.PackageSourceProvenance.Kind != PackageSourceLocalGenerated ||
		record.PackageSourceProvenance.PackageSHA256 != record.PackageHash || provenance == nil {
		return record
	}
	importID := strings.TrimSpace(provenance.ImportID)
	distribution := strings.TrimSpace(provenance.Distribution)
	if importID == "" || importID != distribution ||
		distribution != strings.TrimSpace(record.PackageSourceProvenance.SourceReference) ||
		strings.TrimSpace(provenance.PolicyEpoch) == "" || strings.TrimSpace(provenance.UnsignedPolicy) == "" {
		return record
	}
	assessedAt, err := time.Parse(time.RFC3339Nano, provenance.AssessedAt)
	if err != nil || assessedAt.IsZero() {
		return record
	}
	record.ExecutionApproval = ExecutionApproval{
		Status:            ExecutionApprovalUserApproved,
		OwnerEnvHash:      record.OwnerEnvHash,
		PackageSHA256:     record.PackageHash,
		ReasonCodes:       []string{"explicit_local_import"},
		EvidenceReference: importID,
		PolicyEpoch:       provenance.PolicyEpoch,
		AssessedAt:        assessedAt,
		ApprovedAt:        assessedAt,
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
