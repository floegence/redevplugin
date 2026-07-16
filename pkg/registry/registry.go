package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
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

type RetainedDataState string

const (
	RetainedDataNone              RetainedDataState = "none"
	RetainedDataRetained          RetainedDataState = "retained"
	RetainedDataDeleted           RetainedDataState = "deleted"
	RetainedDataDeleteFailedRetry RetainedDataState = "delete_failed_retryable"
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

type PluginRecord struct {
	PluginInstanceID         string                   `json:"plugin_instance_id"`
	PublisherID              string                   `json:"publisher_id"`
	PluginID                 string                   `json:"plugin_id"`
	Version                  string                   `json:"version"`
	ActiveFingerprint        string                   `json:"active_fingerprint"`
	PackageHash              string                   `json:"package_hash"`
	ManifestHash             string                   `json:"manifest_hash"`
	EntriesHash              string                   `json:"entries_hash"`
	TrustState               TrustState               `json:"trust_state"`
	TrustAssessment          TrustAssessment          `json:"trust_assessment"`
	SourcePolicySnapshotHash string                   `json:"source_policy_snapshot_hash,omitempty"`
	SourcePolicySnapshot     map[string]any           `json:"source_policy_snapshot,omitempty"`
	LocalImportProvenance    *LocalImportProvenance   `json:"local_import_provenance,omitempty"`
	CapabilityContracts      []capabilitycontract.Pin `json:"capability_contracts,omitempty"`
	EnableState              EnableState              `json:"enable_state"`
	DisabledReason           string                   `json:"disabled_reason,omitempty"`
	RetainedDataState        RetainedDataState        `json:"retained_data_state"`
	PolicyRevision           uint64                   `json:"policy_revision"`
	ManagementRevision       uint64                   `json:"management_revision"`
	RevokeEpoch              uint64                   `json:"revoke_epoch"`
	Manifest                 manifest.Manifest        `json:"manifest"`
	PackageEntries           []pluginpkg.Entry        `json:"package_entries"`
	VersionHistory           []PluginVersion          `json:"version_history,omitempty"`
	InstalledAt              time.Time                `json:"installed_at"`
	EnabledAt                *time.Time               `json:"enabled_at,omitempty"`
	UpdatedAt                time.Time                `json:"updated_at"`
	DeletedAt                *time.Time               `json:"deleted_at,omitempty"`
	Metadata                 map[string]string        `json:"metadata,omitempty"`
}

type PluginVersion struct {
	Version                  string                   `json:"version"`
	ActiveFingerprint        string                   `json:"active_fingerprint"`
	PackageHash              string                   `json:"package_hash"`
	ManifestHash             string                   `json:"manifest_hash"`
	EntriesHash              string                   `json:"entries_hash"`
	TrustState               TrustState               `json:"trust_state"`
	TrustAssessment          TrustAssessment          `json:"trust_assessment"`
	SourcePolicySnapshotHash string                   `json:"source_policy_snapshot_hash,omitempty"`
	SourcePolicySnapshot     map[string]any           `json:"source_policy_snapshot,omitempty"`
	LocalImportProvenance    *LocalImportProvenance   `json:"local_import_provenance,omitempty"`
	CapabilityContracts      []capabilitycontract.Pin `json:"capability_contracts,omitempty"`
	Manifest                 manifest.Manifest        `json:"manifest"`
	PackageEntries           []pluginpkg.Entry        `json:"package_entries"`
	ActivatedAt              time.Time                `json:"activated_at"`
	Metadata                 map[string]string        `json:"metadata,omitempty"`
}

type LocalImportProvenance struct {
	ImportID       string `json:"import_id"`
	Distribution   string `json:"distribution"`
	PolicyEpoch    string `json:"policy_epoch"`
	UnsignedPolicy string `json:"unsigned_policy"`
	AssessedAt     string `json:"assessed_at"`
}

type SourceSecurityFloor struct {
	SourceID                 string    `json:"source_id"`
	PolicyEpoch              string    `json:"policy_epoch"`
	KeyRotationEpoch         string    `json:"key_rotation_epoch"`
	RevocationEpoch          string    `json:"revocation_epoch"`
	SourcePolicySnapshotHash string    `json:"source_policy_snapshot_hash"`
	RevocationMetadataSHA256 string    `json:"revocation_metadata_sha256"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type PutOptions struct {
	Now time.Time
}

type Store interface {
	PutPlugin(ctx context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error)
	GetPlugin(ctx context.Context, pluginInstanceID string) (PluginRecord, error)
	ListPlugins(ctx context.Context) ([]PluginRecord, error)
	SetEnableState(ctx context.Context, pluginInstanceID string, state EnableState, reason string, now time.Time) (PluginRecord, error)
	BumpPolicyRevision(ctx context.Context, pluginInstanceID string, revoke bool, now time.Time) (PluginRecord, error)
	MarkUninstalled(ctx context.Context, pluginInstanceID string, retained RetainedDataState, now time.Time) (PluginRecord, error)
	DeletePlugin(ctx context.Context, pluginInstanceID string) error
	PutSourceSecurityFloor(ctx context.Context, floor SourceSecurityFloor, opts PutOptions) (SourceSecurityFloor, error)
	GetSourceSecurityFloor(ctx context.Context, sourceID string) (SourceSecurityFloor, error)
}

var ErrNotFound = errors.New("plugin record not found")
var ErrSourceSecurityFloorRollback = errors.New("source security floor rollback")

type MemoryStore struct {
	mu           sync.RWMutex
	records      map[string]PluginRecord
	sourceFloors map[string]SourceSecurityFloor
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records:      map[string]PluginRecord{},
		sourceFloors: map[string]SourceSecurityFloor{},
	}
}

func (s *MemoryStore) PutPlugin(_ context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error) {
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
	existing, exists := s.records[record.PluginInstanceID]
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
	if record.RetainedDataState == "" {
		record.RetainedDataState = RetainedDataNone
	}
	record = normalizeTrustAssessment(record)
	s.records[record.PluginInstanceID] = record
	return clonePluginRecord(record)
}

func (s *MemoryStore) GetPlugin(_ context.Context, pluginInstanceID string) (PluginRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	return clonePluginRecord(record)
}

func (s *MemoryStore) ListPlugins(_ context.Context) ([]PluginRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]PluginRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.DeletedAt == nil {
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

func (s *MemoryStore) SetEnableState(_ context.Context, pluginInstanceID string, state EnableState, reason string, now time.Time) (PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[pluginInstanceID]
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
	s.records[pluginInstanceID] = record
	return clonePluginRecord(record)
}

func (s *MemoryStore) BumpPolicyRevision(_ context.Context, pluginInstanceID string, revoke bool, now time.Time) (PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.PolicyRevision++
	if revoke {
		record.RevokeEpoch++
	}
	record.UpdatedAt = now
	s.records[pluginInstanceID] = record
	return clonePluginRecord(record)
}

func (s *MemoryStore) MarkUninstalled(_ context.Context, pluginInstanceID string, retained RetainedDataState, now time.Time) (PluginRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record.EnableState = EnableDisabled
	record.DisabledReason = "uninstalled"
	record.RetainedDataState = retained
	record.ManagementRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	record.DeletedAt = &now
	record.EnabledAt = nil
	s.records[pluginInstanceID] = record
	return clonePluginRecord(record)
}

func (s *MemoryStore) DeletePlugin(_ context.Context, pluginInstanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.records[pluginInstanceID]; !ok {
		return ErrNotFound
	}
	delete(s.records, pluginInstanceID)
	return nil
}

func (s *MemoryStore) PutSourceSecurityFloor(_ context.Context, floor SourceSecurityFloor, opts PutOptions) (SourceSecurityFloor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	floor.UpdatedAt = now
	if err := validateSourceSecurityFloor(floor); err != nil {
		return SourceSecurityFloor{}, err
	}
	if existing, ok := s.sourceFloors[floor.SourceID]; ok {
		if err := ensureSourceSecurityFloorMonotonic(existing, floor); err != nil {
			return SourceSecurityFloor{}, err
		}
	}
	s.sourceFloors[floor.SourceID] = floor
	return floor, nil
}

func (s *MemoryStore) GetSourceSecurityFloor(_ context.Context, sourceID string) (SourceSecurityFloor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	floor, ok := s.sourceFloors[sourceID]
	if !ok {
		return SourceSecurityFloor{}, ErrNotFound
	}
	return floor, nil
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
	raw, err := json.Marshal(record)
	if err != nil {
		return PluginRecord{}, err
	}
	var cloned PluginRecord
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return PluginRecord{}, err
	}
	return cloned, nil
}

func validateSourceSecurityFloor(floor SourceSecurityFloor) error {
	if floor.SourceID == "" {
		return errors.New("source_id is required")
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{name: "policy_epoch", value: floor.PolicyEpoch},
		{name: "key_rotation_epoch", value: floor.KeyRotationEpoch},
		{name: "revocation_epoch", value: floor.RevocationEpoch},
	} {
		if _, err := parseSourceSecurityEpoch(item.value); err != nil {
			return fmt.Errorf("%s is invalid: %w", item.name, err)
		}
	}
	if floor.SourcePolicySnapshotHash == "" {
		return errors.New("source_policy_snapshot_hash is required")
	}
	if floor.RevocationMetadataSHA256 == "" {
		return errors.New("revocation_metadata_sha256 is required")
	}
	return nil
}

func ensureSourceSecurityFloorMonotonic(existing SourceSecurityFloor, next SourceSecurityFloor) error {
	for _, item := range []struct {
		name     string
		existing string
		next     string
	}{
		{name: "policy_epoch", existing: existing.PolicyEpoch, next: next.PolicyEpoch},
		{name: "key_rotation_epoch", existing: existing.KeyRotationEpoch, next: next.KeyRotationEpoch},
		{name: "revocation_epoch", existing: existing.RevocationEpoch, next: next.RevocationEpoch},
	} {
		cmp, err := compareSourceSecurityEpoch(item.next, item.existing)
		if err != nil {
			return err
		}
		if cmp < 0 {
			return fmt.Errorf("%w: %s moved from %s to %s", ErrSourceSecurityFloorRollback, item.name, item.existing, item.next)
		}
	}
	cmp, err := compareSourceSecurityEpoch(next.RevocationEpoch, existing.RevocationEpoch)
	if err != nil {
		return err
	}
	if cmp == 0 && next.RevocationMetadataSHA256 != existing.RevocationMetadataSHA256 {
		return fmt.Errorf("%w: revocation_metadata_sha256 changed for epoch %s", ErrSourceSecurityFloorRollback, existing.RevocationEpoch)
	}
	cmp, err = compareSourceSecurityEpoch(next.PolicyEpoch, existing.PolicyEpoch)
	if err != nil {
		return err
	}
	if cmp == 0 && next.SourcePolicySnapshotHash != existing.SourcePolicySnapshotHash {
		return fmt.Errorf("%w: source_policy_snapshot_hash changed for epoch %s", ErrSourceSecurityFloorRollback, existing.PolicyEpoch)
	}
	return nil
}

func compareSourceSecurityEpoch(left string, right string) (int, error) {
	leftValue, err := parseSourceSecurityEpoch(left)
	if err != nil {
		return 0, err
	}
	rightValue, err := parseSourceSecurityEpoch(right)
	if err != nil {
		return 0, err
	}
	switch {
	case leftValue < rightValue:
		return -1, nil
	case leftValue > rightValue:
		return 1, nil
	default:
		return 0, nil
	}
}

func parseSourceSecurityEpoch(value string) (uint64, error) {
	if value == "" {
		return 0, errors.New("epoch is required")
	}
	if strings.TrimSpace(value) != value {
		return 0, errors.New("epoch must be canonical decimal")
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, errors.New("epoch must be canonical decimal")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("epoch must be canonical decimal")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func RunnableTrustState(state TrustState) bool {
	switch state {
	case TrustVerified, TrustUnsignedLocal:
		return true
	default:
		return false
	}
}
