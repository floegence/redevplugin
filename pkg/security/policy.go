package security

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	PolicyDenyReasonMethodDenied         = "method_denied"
	PolicyDenyReasonPermissionNotAllowed = "permission_not_allowed"
)

type PolicyRecord struct {
	PluginInstanceID   string    `json:"plugin_instance_id"`
	AllowedPermissions []string  `json:"allowed_permissions,omitempty"`
	DeniedMethods      []string  `json:"denied_methods,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type PutPolicyRequest struct {
	PluginInstanceID   string    `json:"plugin_instance_id"`
	AllowedPermissions []string  `json:"allowed_permissions,omitempty"`
	DeniedMethods      []string  `json:"denied_methods,omitempty"`
	Now                time.Time `json:"now,omitempty"`
}

type EvaluatePolicyRequest struct {
	PluginInstanceID    string   `json:"plugin_instance_id"`
	Method              string   `json:"method"`
	RequiredPermissions []string `json:"required_permissions,omitempty"`
}

type PolicyEvaluation struct {
	Allowed            bool     `json:"allowed"`
	Reason             string   `json:"reason,omitempty"`
	DeniedMethod       string   `json:"denied_method,omitempty"`
	MissingPermissions []string `json:"missing_permissions,omitempty"`
}

type PolicyStore interface {
	PutPolicy(ctx context.Context, req PutPolicyRequest) (PolicyRecord, error)
	GetPolicy(ctx context.Context, pluginInstanceID string) (PolicyRecord, error)
	ListPolicies(ctx context.Context) ([]PolicyRecord, error)
	DeletePolicy(ctx context.Context, pluginInstanceID string) error
	EvaluatePolicy(ctx context.Context, req EvaluatePolicyRequest) (PolicyEvaluation, error)
}

var (
	ErrInvalidPolicy  = errors.New("plugin security policy is invalid")
	ErrPolicyNotFound = errors.New("plugin security policy not found")
	ErrPolicyDenied   = errors.New("plugin security policy denied request")
)

type MemoryPolicyStore struct {
	mu      sync.RWMutex
	records map[string]PolicyRecord
}

func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{records: map[string]PolicyRecord{}}
}

func (s *MemoryPolicyStore) PutPolicy(_ context.Context, req PutPolicyRequest) (PolicyRecord, error) {
	if s == nil {
		return PolicyRecord{}, errors.New("security policy store is nil")
	}
	record, err := policyRecordFromPut(req)
	if err != nil {
		return PolicyRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.PluginInstanceID] = clonePolicyRecord(record)
	return record, nil
}

func (s *MemoryPolicyStore) GetPolicy(_ context.Context, pluginInstanceID string) (PolicyRecord, error) {
	if s == nil {
		return PolicyRecord{}, errors.New("security policy store is nil")
	}
	pluginInstanceID = normalizePolicyID(pluginInstanceID)
	if pluginInstanceID == "" {
		return PolicyRecord{}, ErrInvalidPolicy
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[pluginInstanceID]
	if !ok {
		return PolicyRecord{}, ErrPolicyNotFound
	}
	return clonePolicyRecord(record), nil
}

func (s *MemoryPolicyStore) ListPolicies(_ context.Context) ([]PolicyRecord, error) {
	if s == nil {
		return nil, errors.New("security policy store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]PolicyRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, clonePolicyRecord(record))
	}
	sortPolicyRecords(records)
	return records, nil
}

func (s *MemoryPolicyStore) DeletePolicy(_ context.Context, pluginInstanceID string) error {
	if s == nil {
		return errors.New("security policy store is nil")
	}
	pluginInstanceID = normalizePolicyID(pluginInstanceID)
	if pluginInstanceID == "" {
		return ErrInvalidPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, pluginInstanceID)
	return nil
}

func (s *MemoryPolicyStore) EvaluatePolicy(_ context.Context, req EvaluatePolicyRequest) (PolicyEvaluation, error) {
	if s == nil {
		return PolicyEvaluation{}, errors.New("security policy store is nil")
	}
	pluginInstanceID := normalizePolicyID(req.PluginInstanceID)
	method := normalizePolicyID(req.Method)
	if pluginInstanceID == "" || method == "" {
		return PolicyEvaluation{}, ErrInvalidPolicy
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[pluginInstanceID]
	if !ok {
		return PolicyEvaluation{Allowed: true}, nil
	}
	return evaluatePolicyRecord(record, method, req.RequiredPermissions), nil
}

func policyRecordFromPut(req PutPolicyRequest) (PolicyRecord, error) {
	pluginInstanceID := normalizePolicyID(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return PolicyRecord{}, ErrInvalidPolicy
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return PolicyRecord{
		PluginInstanceID:   pluginInstanceID,
		AllowedPermissions: normalizePolicyStringSet(req.AllowedPermissions),
		DeniedMethods:      normalizePolicyStringSet(req.DeniedMethods),
		UpdatedAt:          now,
	}, nil
}

func evaluatePolicyRecord(record PolicyRecord, method string, requiredPermissions []string) PolicyEvaluation {
	methods := stringSet(record.DeniedMethods)
	if _, denied := methods[method]; denied {
		return PolicyEvaluation{
			Allowed:      false,
			Reason:       PolicyDenyReasonMethodDenied,
			DeniedMethod: method,
		}
	}
	if len(record.AllowedPermissions) == 0 {
		return PolicyEvaluation{Allowed: true}
	}
	allowedPermissions := stringSet(record.AllowedPermissions)
	missing := make([]string, 0)
	for _, permissionID := range normalizePolicyStringSet(requiredPermissions) {
		if _, ok := allowedPermissions[permissionID]; !ok {
			missing = append(missing, permissionID)
		}
	}
	if len(missing) > 0 {
		return PolicyEvaluation{
			Allowed:            false,
			Reason:             PolicyDenyReasonPermissionNotAllowed,
			MissingPermissions: missing,
		}
	}
	return PolicyEvaluation{Allowed: true}
}

func normalizePolicyID(value string) string {
	return strings.TrimSpace(value)
}

func normalizePolicyStringSet(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizePolicyID(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func clonePolicyRecord(record PolicyRecord) PolicyRecord {
	record.AllowedPermissions = append([]string(nil), record.AllowedPermissions...)
	record.DeniedMethods = append([]string(nil), record.DeniedMethods...)
	return record
}

func sortPolicyRecords(records []PolicyRecord) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].PluginInstanceID < records[j].PluginInstanceID
	})
}
