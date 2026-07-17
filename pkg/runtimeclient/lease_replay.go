package runtimeclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrRuntimeLeaseInvalid = errors.New("runtime execution lease is invalid")
	ErrRuntimeLeaseReplay  = errors.New("runtime execution lease has already been consumed")
)

type RuntimeLeaseReplayStore interface {
	ConsumeRuntimeLease(ctx context.Context, req RuntimeLeaseReplayConsumeRequest) (RuntimeLeaseReplayRecord, error)
}

type RuntimeLeaseReplayLister interface {
	ListRuntimeLeaseReplays(ctx context.Context, req RuntimeLeaseReplayListRequest) ([]RuntimeLeaseReplayRecord, error)
}

type RuntimeLeaseReplayConsumeRequest struct {
	Lease  Lease     `json:"lease"`
	Method string    `json:"method"`
	Now    time.Time `json:"now,omitempty"`
}

type RuntimeLeaseReplayListRequest struct {
	PluginInstanceID string `json:"plugin_instance_id,omitempty"`
}

type RuntimeLeaseReplayRecord struct {
	LeaseID             string    `json:"lease_id"`
	LeaseNonceHash      string    `json:"lease_nonce_hash"`
	PluginInstanceID    string    `json:"plugin_instance_id"`
	RuntimeGenerationID string    `json:"runtime_generation_id"`
	Method              string    `json:"method"`
	PolicyRevision      uint64    `json:"policy_revision"`
	ManagementRevision  uint64    `json:"management_revision"`
	RevokeEpoch         uint64    `json:"revoke_epoch"`
	ConsumedAt          time.Time `json:"consumed_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type MemoryRuntimeLeaseReplayStore struct {
	mu      sync.Mutex
	records map[string]RuntimeLeaseReplayRecord
}

func NewMemoryRuntimeLeaseReplayStore() *MemoryRuntimeLeaseReplayStore {
	return &MemoryRuntimeLeaseReplayStore{records: map[string]RuntimeLeaseReplayRecord{}}
}

func (s *MemoryRuntimeLeaseReplayStore) ConsumeRuntimeLease(ctx context.Context, req RuntimeLeaseReplayConsumeRequest) (RuntimeLeaseReplayRecord, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}
	if s == nil {
		return RuntimeLeaseReplayRecord{}, errors.New("runtime lease replay store is nil")
	}
	record, err := runtimeLeaseReplayRecordFromConsume(req)
	if err != nil {
		return RuntimeLeaseReplayRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(record.ConsumedAt)
	if _, exists := s.records[record.LeaseNonceHash]; exists {
		return RuntimeLeaseReplayRecord{}, ErrRuntimeLeaseReplay
	}
	s.records[record.LeaseNonceHash] = record
	return record, nil
}

func (s *MemoryRuntimeLeaseReplayStore) ListRuntimeLeaseReplays(ctx context.Context, req RuntimeLeaseReplayListRequest) ([]RuntimeLeaseReplayRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("runtime lease replay store is nil")
	}
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)

	records := make([]RuntimeLeaseReplayRecord, 0, len(s.records))
	for _, record := range s.records {
		if pluginInstanceID != "" && record.PluginInstanceID != pluginInstanceID {
			continue
		}
		records = append(records, record)
	}
	sortRuntimeLeaseReplayRecords(records)
	return records, nil
}

func (s *MemoryRuntimeLeaseReplayStore) pruneExpiredLocked(now time.Time) {
	for key, record := range s.records {
		if !record.ExpiresAt.After(now) {
			delete(s.records, key)
		}
	}
}

func runtimeLeaseReplayRecordFromConsume(req RuntimeLeaseReplayConsumeRequest) (RuntimeLeaseReplayRecord, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	leaseID := strings.TrimSpace(req.Lease.LeaseID)
	leaseNonce := strings.TrimSpace(req.Lease.LeaseNonce)
	pluginInstanceID := strings.TrimSpace(req.Lease.PluginInstanceID)
	runtimeGenerationID := strings.TrimSpace(req.Lease.RuntimeGenerationID)
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = strings.TrimSpace(req.Lease.Method)
	}
	if leaseID == "" || leaseNonce == "" || pluginInstanceID == "" || runtimeGenerationID == "" || method == "" {
		return RuntimeLeaseReplayRecord{}, ErrRuntimeLeaseInvalid
	}
	expiresAt := time.UnixMilli(req.Lease.ExpiresAtUnixMillis).UTC()
	if req.Lease.ExpiresAtUnixMillis <= 0 || !expiresAt.After(now) {
		return RuntimeLeaseReplayRecord{}, ErrRuntimeLeaseInvalid
	}
	return RuntimeLeaseReplayRecord{
		LeaseID:             leaseID,
		LeaseNonceHash:      runtimeLeaseReplayHash(leaseID, leaseNonce),
		PluginInstanceID:    pluginInstanceID,
		RuntimeGenerationID: runtimeGenerationID,
		Method:              method,
		PolicyRevision:      req.Lease.PolicyRevision,
		ManagementRevision:  req.Lease.ManagementRevision,
		RevokeEpoch:         req.Lease.RevokeEpoch,
		ConsumedAt:          now.UTC(),
		ExpiresAt:           expiresAt,
	}, nil
}

func sortRuntimeLeaseReplayRecords(records []RuntimeLeaseReplayRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].ConsumedAt.Equal(records[j].ConsumedAt) {
			return records[i].ConsumedAt.Before(records[j].ConsumedAt)
		}
		return records[i].LeaseID < records[j].LeaseID
	})
}

func runtimeLeaseReplayHash(leaseID string, leaseNonce string) string {
	sum := sha256.Sum256([]byte(leaseID + "\x00" + leaseNonce))
	return "sha256:" + hex.EncodeToString(sum[:])
}
