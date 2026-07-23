package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/plugindata"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/security"
)

type TrustState string

const (
	TrustVerified        TrustState = "verified"
	TrustUnsignedLocal   TrustState = "unsigned_local"
	TrustUntrusted       TrustState = "untrusted"
	TrustNeedsReview     TrustState = "needs_review"
	TrustUnavailable     TrustState = "trust_unavailable"
	TrustBlockedSecurity TrustState = "blocked_security"
)

type EnableState string

const (
	EnableDisabled             EnableState = "disabled"
	EnableEnabled              EnableState = "enabled"
	EnableDisabledByPolicy     EnableState = "disabled_by_policy"
	EnableDisabledIncompatible EnableState = "disabled_incompatible"
)

type TrustHashSet struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type VerifiedSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
}

type TrustAssessment struct {
	TrustState           TrustState         `json:"trust_state"`
	ReasonCodes          []string           `json:"reason_codes,omitempty"`
	VerifiedHashes       TrustHashSet       `json:"verified_hashes"`
	VerifiedSignature    *VerifiedSignature `json:"verified_signature,omitempty"`
	TrustAssessmentEpoch string             `json:"trust_assessment_epoch,omitempty"`
	PolicyEpoch          string             `json:"policy_epoch,omitempty"`
	RevocationEpoch      string             `json:"revocation_epoch,omitempty"`
	Metadata             map[string]string  `json:"metadata,omitempty"`
}

type ReleaseTrustBinding struct {
	SourceID              string `json:"source_id"`
	Channel               string `json:"channel"`
	ReleaseMetadataRef    string `json:"release_metadata_ref"`
	ReleaseMetadataSHA256 string `json:"release_metadata_sha256"`
	PublisherID           string `json:"publisher_id"`
	PluginID              string `json:"plugin_id"`
	Version               string `json:"version"`
	VerifiedStateSHA256   string `json:"verified_state_sha256"`
	RootEpoch             string `json:"root_epoch"`
	PolicyEpoch           string `json:"policy_epoch"`
	RevocationEpoch       string `json:"revocation_epoch"`
}

type PluginRecord struct {
	OwnerEnvHash              string                    `json:"-"`
	PluginInstanceID          string                    `json:"plugin_instance_id"`
	PublisherID               string                    `json:"publisher_id"`
	PluginID                  string                    `json:"plugin_id"`
	Version                   string                    `json:"version"`
	ActiveFingerprint         string                    `json:"active_fingerprint"`
	PackageHash               string                    `json:"package_hash"`
	ManifestHash              string                    `json:"manifest_hash"`
	EntriesHash               string                    `json:"entries_hash"`
	TrustState                TrustState                `json:"trust_state"`
	TrustAssessment           TrustAssessment           `json:"trust_assessment"`
	SignatureAssessment       SignatureAssessment       `json:"signature_assessment"`
	PackageSourceProvenance   PackageSourceProvenance   `json:"source_provenance"`
	ExecutionApproval         ExecutionApproval         `json:"execution_approval"`
	UpdateEligibility         UpdateEligibility         `json:"update_eligibility"`
	SecurityCapabilitySummary SecurityCapabilitySummary `json:"security_summary"`
	ReleaseTrustBinding       *ReleaseTrustBinding      `json:"release_trust_binding,omitempty"`
	LocalImportProvenance     *LocalImportProvenance    `json:"local_import_provenance,omitempty"`
	CapabilityContracts       []capabilitycontract.Pin  `json:"capability_contracts,omitempty"`
	EnableState               EnableState               `json:"enable_state"`
	DisabledReason            string                    `json:"disabled_reason,omitempty"`
	PolicyRevision            uint64                    `json:"policy_revision"`
	ManagementRevision        uint64                    `json:"management_revision"`
	RevokeEpoch               uint64                    `json:"revoke_epoch"`
	Manifest                  manifest.Manifest         `json:"manifest"`
	PackageEntries            []pluginpkg.Entry         `json:"package_entries"`
	RuntimeRequirement        *RuntimeRequirement       `json:"runtime_requirement,omitempty"`
	VersionHistory            []PluginVersion           `json:"version_history,omitempty"`
	InstalledAt               time.Time                 `json:"installed_at"`
	EnabledAt                 *time.Time                `json:"enabled_at,omitempty"`
	UpdatedAt                 time.Time                 `json:"updated_at"`
	DeletedAt                 *time.Time                `json:"deleted_at,omitempty"`
	Metadata                  map[string]string         `json:"metadata,omitempty"`
}

type PluginVersion struct {
	Version                   string                    `json:"version"`
	ActiveFingerprint         string                    `json:"active_fingerprint"`
	PackageHash               string                    `json:"package_hash"`
	ManifestHash              string                    `json:"manifest_hash"`
	EntriesHash               string                    `json:"entries_hash"`
	TrustState                TrustState                `json:"trust_state"`
	TrustAssessment           TrustAssessment           `json:"trust_assessment"`
	SignatureAssessment       SignatureAssessment       `json:"signature_assessment"`
	PackageSourceProvenance   PackageSourceProvenance   `json:"source_provenance"`
	ExecutionApproval         ExecutionApproval         `json:"execution_approval"`
	UpdateEligibility         UpdateEligibility         `json:"update_eligibility"`
	SecurityCapabilitySummary SecurityCapabilitySummary `json:"security_summary"`
	ReleaseTrustBinding       *ReleaseTrustBinding      `json:"release_trust_binding,omitempty"`
	LocalImportProvenance     *LocalImportProvenance    `json:"local_import_provenance,omitempty"`
	CapabilityContracts       []capabilitycontract.Pin  `json:"capability_contracts,omitempty"`
	Manifest                  manifest.Manifest         `json:"manifest"`
	PackageEntries            []pluginpkg.Entry         `json:"package_entries"`
	RuntimeRequirement        *RuntimeRequirement       `json:"runtime_requirement,omitempty"`
	ActivatedAt               time.Time                 `json:"activated_at"`
	Metadata                  map[string]string         `json:"metadata,omitempty"`
}

// RuntimeRequirement is the exact worker-runtime compatibility contract that
// was verified for an installed package version. UI-only packages leave it nil.
type RuntimeRequirement struct {
	MinVersion       string                 `json:"min_version"`
	SupportedTargets []runtimetarget.Target `json:"supported_targets,omitempty"`
}

type LocalImportProvenance struct {
	ImportID       string `json:"import_id"`
	Distribution   string `json:"distribution"`
	PolicyEpoch    string `json:"policy_epoch"`
	UnsignedPolicy string `json:"unsigned_policy"`
	AssessedAt     string `json:"assessed_at"`
}

type PutOptions struct {
	Now time.Time `json:"-"`
}

type AuthorizationStore interface {
	GrantPermission(ctx context.Context, req permissions.GrantRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error)
	RevokePermission(ctx context.Context, req permissions.RevokeRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error)
	PutSecurityPolicy(ctx context.Context, req security.PutPolicyRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error)
	DeleteSecurityPolicy(ctx context.Context, pluginInstanceID string, now time.Time, expected AuthorizationRevisions) (AuthorizationSnapshot, error)
	GetAuthorization(ctx context.Context, pluginInstanceID string) (AuthorizationSnapshot, error)
	ListAuthorization(ctx context.Context) ([]AuthorizationSnapshot, error)
	Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizationDecision, error)
}

type Store interface {
	Durable() bool
	AuthorizationStore
	ExternalPackageStore
	plugindata.Catalog
	PutPlugin(ctx context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error)
	GetPlugin(ctx context.Context, pluginInstanceID string) (PluginRecord, error)
	ListPlugins(ctx context.Context) ([]PluginRecord, error)
	SetEnableState(ctx context.Context, pluginInstanceID string, state EnableState, reason string, now time.Time) (PluginRecord, error)
	CommitUninstall(ctx context.Context, req plugindata.CommitUninstallRequest) (plugindata.CommitUninstallResult, error)
	AbortInstall(ctx context.Context, pluginInstanceID string) error
}

var ErrNotFound = errors.New("plugin record not found")

type MemoryStore struct {
	mu                     sync.RWMutex
	records                map[string]PluginRecord
	permissionGrants       map[string]map[string]permissions.Record
	securityPolicies       map[string]security.PolicyRecord
	dataBindings           map[string]plugindata.Binding
	dataObjects            map[string]plugindata.Object
	externalPackageCommits map[string]externalPackageCommitReceipt
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records:                map[string]PluginRecord{},
		permissionGrants:       map[string]map[string]permissions.Record{},
		securityPolicies:       map[string]security.PolicyRecord{},
		dataBindings:           map[string]plugindata.Binding{},
		dataObjects:            map[string]plugindata.Object{},
		externalPackageCommits: map[string]externalPackageCommitReceipt{},
	}
}

func (*MemoryStore) Durable() bool { return false }

func (s *MemoryStore) PutPlugin(ctx context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return PluginRecord{}, err
	}
	if record.OwnerEnvHash != "" && record.OwnerEnvHash != ownerEnvHash {
		return PluginRecord{}, ErrOwnerScopeMismatch
	}
	record.OwnerEnvHash = ownerEnvHash
	s.mu.Lock()
	defer s.mu.Unlock()

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if record.PluginInstanceID == "" {
		return PluginRecord{}, errors.New("plugin_instance_id is required")
	}
	cloned, err := clonePluginRecord(record)
	if err != nil {
		return PluginRecord{}, fmt.Errorf("clone plugin record: %w", err)
	}
	record = cloned
	key := environmentRecordKey(ownerEnvHash, record.PluginInstanceID)
	existing, exists := s.records[key]
	if exists {
		record.InstalledAt = existing.InstalledAt
		record.ManagementRevision = existing.ManagementRevision + 1
		record.PolicyRevision = existing.PolicyRevision
		record.RevokeEpoch = existing.RevokeEpoch + 1
	} else {
		record.InstalledAt = now
		if record.PolicyRevision == 0 {
			record.PolicyRevision = 1
		}
		if record.ManagementRevision == 0 {
			record.ManagementRevision = 1
		}
	}
	record.UpdatedAt = now
	record = normalizePluginSecurityFacts(record)
	if err := validatePersistedPluginSecurityFacts(record); err != nil {
		return PluginRecord{}, err
	}
	s.records[key] = record
	return clonePluginRecord(record)
}

func (s *MemoryStore) GetPlugin(ctx context.Context, pluginInstanceID string) (PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return PluginRecord{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.records[environmentRecordKey(ownerEnvHash, pluginInstanceID)]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	return clonePluginRecord(record)
}

func (s *MemoryStore) ListPlugins(ctx context.Context) ([]PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]PluginRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.OwnerEnvHash == ownerEnvHash && record.DeletedAt == nil {
			cloned, err := clonePluginRecord(record)
			if err != nil {
				return nil, fmt.Errorf("clone plugin record: %w", err)
			}
			records = append(records, cloned)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].PluginID == records[j].PluginID {
			return records[i].PluginInstanceID < records[j].PluginInstanceID
		}
		return records[i].PluginID < records[j].PluginID
	})
	return records, nil
}

func (s *MemoryStore) SetEnableState(ctx context.Context, pluginInstanceID string, state EnableState, reason string, now time.Time) (PluginRecord, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return PluginRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := environmentRecordKey(ownerEnvHash, pluginInstanceID)
	record, ok := s.records[key]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.EnableState = state
	record.DisabledReason = reason
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	if state == EnableEnabled {
		record.EnabledAt = &now
	} else {
		record.EnabledAt = nil
	}
	s.records[key] = record
	return clonePluginRecord(record)
}

func (s *MemoryStore) CommitUninstall(ctx context.Context, req plugindata.CommitUninstallRequest) (plugindata.CommitUninstallResult, error) {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return plugindata.CommitUninstallResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := environmentRecordKey(ownerEnvHash, req.PluginInstanceID)
	record, ok := s.records[key]
	if !ok || record.DeletedAt != nil {
		return plugindata.CommitUninstallResult{}, ErrNotFound
	}
	if req.ExpectedManagementRevision == 0 || record.ManagementRevision != req.ExpectedManagementRevision {
		return plugindata.CommitUninstallResult{}, &ManagementRevisionConflictError{PluginInstanceID: req.PluginInstanceID, Expected: req.ExpectedManagementRevision, Actual: record.ManagementRevision}
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	binding, hasBinding := s.dataBindings[key]
	record.EnableState = EnableDisabled
	record.DisabledReason = "uninstalled"
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	record.DeletedAt = &now
	record.EnabledAt = nil
	s.records[key] = record
	delete(s.permissionGrants, key)
	delete(s.securityPolicies, key)
	if hasBinding {
		if req.DeleteData {
			delete(s.dataBindings, key)
		} else {
			binding.State = plugindata.BindingRetained
			binding.Revision++
			binding.RetainedAt = &now
			binding.ExpiresAt = cloneRegistryTime(req.RetainUntil)
			s.dataBindings[key] = binding
		}
	}
	return plugindata.CommitUninstallResult{ManagementRevision: record.ManagementRevision, RevokeEpoch: record.RevokeEpoch, DeletedAt: now}, nil
}

func (s *MemoryStore) AbortInstall(ctx context.Context, pluginInstanceID string) error {
	ownerEnvHash, err := environmentOwner(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := environmentRecordKey(ownerEnvHash, pluginInstanceID)
	if _, ok := s.records[key]; !ok {
		return ErrNotFound
	}
	delete(s.records, key)
	delete(s.permissionGrants, key)
	delete(s.securityPolicies, key)
	delete(s.dataBindings, key)
	return nil
}

func normalizeTrustAssessment(record PluginRecord) PluginRecord {
	if record.TrustAssessment.TrustState == "" {
		record.TrustAssessment.TrustState = record.TrustState
	}
	if record.TrustAssessment.TrustState != "" {
		record.TrustState = record.TrustAssessment.TrustState
	}
	if record.TrustAssessment.VerifiedHashes.PackageSHA256 == "" {
		record.TrustAssessment.VerifiedHashes.PackageSHA256 = record.PackageHash
	}
	if record.TrustAssessment.VerifiedHashes.ManifestSHA256 == "" {
		record.TrustAssessment.VerifiedHashes.ManifestSHA256 = record.ManifestHash
	}
	if record.TrustAssessment.VerifiedHashes.EntriesSHA256 == "" {
		record.TrustAssessment.VerifiedHashes.EntriesSHA256 = record.EntriesHash
	}
	return record
}

func clonePluginRecord(record PluginRecord) (PluginRecord, error) {
	ownerEnvHash := record.OwnerEnvHash
	raw, err := json.Marshal(record)
	if err != nil {
		return PluginRecord{}, err
	}
	var cloned PluginRecord
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return PluginRecord{}, err
	}
	cloned.OwnerEnvHash = ownerEnvHash
	return cloned, nil
}

func RunnableTrustState(state TrustState) bool {
	switch state {
	case TrustVerified, TrustUnsignedLocal:
		return true
	default:
		return false
	}
}

// RunnablePluginRecord preserves the legacy trust projection for records that
// predate external-package facts. External packages are governed by their
// environment-and-package-bound execution approval instead of signature state.
func RunnablePluginRecord(record PluginRecord) bool {
	switch record.PackageSourceProvenance.Kind {
	case PackageSourcePackageURL, PackageSourceGitHubRepository,
		PackageSourceOfficialCatalog, PackageSourceApprovedCatalog:
		if !validSignatureAssessmentStatus(record.SignatureAssessment.Status) ||
			!validExecutionApprovalStatus(record.ExecutionApproval.Status) {
			return false
		}
		if record.SignatureAssessment.Status == SignatureInvalid || record.SignatureAssessment.Status == SignatureRevoked {
			return false
		}
		return record.ExecutionApproval.Status == ExecutionApprovalUserApproved ||
			record.ExecutionApproval.Status == ExecutionApprovalPolicyApproved
	case "":
		// New package records are checked before Registry persistence normalizes
		// their source facts. This narrow fallback must not accept a partially
		// populated or future external-package security projection.
		if record.SignatureAssessment.Status != "" || record.ExecutionApproval.Status != "" {
			return false
		}
		return RunnableTrustState(record.TrustState)
	case PackageSourceLocalGenerated, PackageSourceLegacyRegistry:
		if !validSignatureAssessmentStatus(record.SignatureAssessment.Status) ||
			!validExecutionApprovalStatus(record.ExecutionApproval.Status) {
			return false
		}
		if record.SignatureAssessment.Status == SignatureInvalid || record.SignatureAssessment.Status == SignatureRevoked {
			return false
		}
		return RunnableTrustState(record.TrustState)
	default:
		return false
	}
}
