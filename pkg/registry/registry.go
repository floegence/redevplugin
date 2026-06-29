package registry

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

type TrustState string

const (
	TrustBundled         TrustState = "bundled"
	TrustVerified        TrustState = "verified"
	TrustUnsignedLocal   TrustState = "unsigned_local"
	TrustUntrusted       TrustState = "untrusted"
	TrustNeedsReview     TrustState = "needs_review"
	TrustBlockedSecurity TrustState = "blocked_security"
)

type EnableState string

const (
	EnableDisabled         EnableState = "disabled"
	EnableEnabled          EnableState = "enabled"
	EnableDisabledByPolicy EnableState = "disabled_by_policy"
)

type RetainedDataState string

const (
	RetainedDataNone              RetainedDataState = "none"
	RetainedDataRetained          RetainedDataState = "retained"
	RetainedDataDeleted           RetainedDataState = "deleted"
	RetainedDataDeleteFailedRetry RetainedDataState = "delete_failed_retryable"
)

type PluginRecord struct {
	PluginInstanceID   string            `json:"plugin_instance_id"`
	PublisherID        string            `json:"publisher_id"`
	PluginID           string            `json:"plugin_id"`
	Version            string            `json:"version"`
	ActiveFingerprint  string            `json:"active_fingerprint"`
	PackageHash        string            `json:"package_hash"`
	ManifestHash       string            `json:"manifest_hash"`
	EntriesHash        string            `json:"entries_hash"`
	TrustState         TrustState        `json:"trust_state"`
	EnableState        EnableState       `json:"enable_state"`
	DisabledReason     string            `json:"disabled_reason,omitempty"`
	RetainedDataState  RetainedDataState `json:"retained_data_state"`
	PolicyRevision     uint64            `json:"policy_revision"`
	ManagementRevision uint64            `json:"management_revision"`
	RevokeEpoch        uint64            `json:"revoke_epoch"`
	Manifest           manifest.Manifest `json:"manifest"`
	PackageEntries     []pluginpkg.Entry `json:"package_entries"`
	InstalledAt        time.Time         `json:"installed_at"`
	EnabledAt          *time.Time        `json:"enabled_at,omitempty"`
	UpdatedAt          time.Time         `json:"updated_at"`
	DeletedAt          *time.Time        `json:"deleted_at,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type PutOptions struct {
	Now time.Time
}

type Store interface {
	PutPlugin(ctx context.Context, record PluginRecord, opts PutOptions) (PluginRecord, error)
	GetPlugin(ctx context.Context, pluginInstanceID string) (PluginRecord, error)
	ListPlugins(ctx context.Context) ([]PluginRecord, error)
	SetEnableState(ctx context.Context, pluginInstanceID string, state EnableState, reason string, now time.Time) (PluginRecord, error)
	MarkUninstalled(ctx context.Context, pluginInstanceID string, retained RetainedDataState, now time.Time) (PluginRecord, error)
	DeletePlugin(ctx context.Context, pluginInstanceID string) error
}

var ErrNotFound = errors.New("plugin record not found")

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]PluginRecord
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]PluginRecord{}}
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
	s.records[record.PluginInstanceID] = record
	return record, nil
}

func (s *MemoryStore) GetPlugin(_ context.Context, pluginInstanceID string) (PluginRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *MemoryStore) ListPlugins(_ context.Context) ([]PluginRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]PluginRecord, 0, len(s.records))
	for _, record := range s.records {
		if record.DeletedAt == nil {
			records = append(records, record)
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
	return record, nil
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
	return record, nil
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

func RunnableTrustState(state TrustState) bool {
	switch state {
	case TrustBundled, TrustVerified, TrustUnsignedLocal:
		return true
	default:
		return false
	}
}
