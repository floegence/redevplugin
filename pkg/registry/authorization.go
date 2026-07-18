package registry

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/permissions"
	"github.com/floegence/redevplugin/pkg/security"
)

type AuthorizationRevisions struct {
	PolicyRevision     uint64 `json:"policy_revision"`
	ManagementRevision uint64 `json:"management_revision"`
	RevokeEpoch        uint64 `json:"revoke_epoch"`
}

func AuthorizationRevisionsFromRecord(record PluginRecord) AuthorizationRevisions {
	return AuthorizationRevisions{
		PolicyRevision:     record.PolicyRevision,
		ManagementRevision: record.ManagementRevision,
		RevokeEpoch:        record.RevokeEpoch,
	}
}

type AuthorizationSnapshot struct {
	Plugin PluginRecord           `json:"plugin"`
	Grants []permissions.Record   `json:"grants"`
	Policy *security.PolicyRecord `json:"policy,omitempty"`
}

type AuthorizationState struct {
	PluginInstanceID  string                 `json:"plugin_instance_id"`
	PluginVersion     string                 `json:"plugin_version"`
	ActiveFingerprint string                 `json:"active_fingerprint"`
	TrustState        TrustState             `json:"trust_state"`
	EnableState       EnableState            `json:"enable_state"`
	Revisions         AuthorizationRevisions `json:"revisions"`
}

func authorizationStateFromRecord(record PluginRecord) AuthorizationState {
	return AuthorizationState{
		PluginInstanceID:  record.PluginInstanceID,
		PluginVersion:     record.Version,
		ActiveFingerprint: record.ActiveFingerprint,
		TrustState:        record.TrustState,
		EnableState:       record.EnableState,
		Revisions:         AuthorizationRevisionsFromRecord(record),
	}
}

type AuthorizeRequest struct {
	PluginInstanceID string                 `json:"plugin_instance_id"`
	Method           string                 `json:"method"`
	PermissionIDs    []string               `json:"permission_ids,omitempty"`
	Expected         AuthorizationRevisions `json:"expected"`
	Now              time.Time              `json:"now,omitempty"`
}

type AuthorizationDecision struct {
	State              AuthorizationState        `json:"state"`
	Allowed            bool                      `json:"allowed"`
	MissingPermissions []string                  `json:"missing_permissions,omitempty"`
	PolicyEvaluation   security.PolicyEvaluation `json:"policy_evaluation"`
}

var (
	ErrInvalidAuthorizationRevisions = errors.New("authorization revisions are invalid")
	ErrAuthorizationRevisionConflict = errors.New("authorization revision conflict")
)

type AuthorizationRevisionConflictError struct {
	PluginInstanceID string
	Expected         AuthorizationRevisions
	Actual           AuthorizationRevisions
}

func (e *AuthorizationRevisionConflictError) Error() string {
	return fmt.Sprintf(
		"%s for plugin %q: expected policy=%d management=%d revoke=%d, actual policy=%d management=%d revoke=%d",
		ErrAuthorizationRevisionConflict,
		e.PluginInstanceID,
		e.Expected.PolicyRevision,
		e.Expected.ManagementRevision,
		e.Expected.RevokeEpoch,
		e.Actual.PolicyRevision,
		e.Actual.ManagementRevision,
		e.Actual.RevokeEpoch,
	)
}

func (e *AuthorizationRevisionConflictError) Unwrap() error {
	return ErrAuthorizationRevisionConflict
}

func (s *MemoryStore) GrantPermission(_ context.Context, req permissions.GrantRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	grant, err := permissions.NewGrant(req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.requireAuthorizationMutationLocked(grant.PluginInstanceID, expected)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	grants := s.permissionGrants[record.PluginInstanceID]
	if grants == nil {
		grants = map[string]permissions.Record{}
		s.permissionGrants[record.PluginInstanceID] = grants
	}
	grants[grant.PermissionID] = permissions.CloneRecord(grant)
	record.PolicyRevision++
	record.UpdatedAt = grant.GrantedAt
	s.records[record.PluginInstanceID] = record
	return s.authorizationSnapshotLocked(record)
}

func (s *MemoryStore) RevokePermission(_ context.Context, req permissions.RevokeRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	if err := permissions.ValidateRevokeRequest(req); err != nil {
		return AuthorizationSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	record, err := s.requireAuthorizationMutationLocked(pluginInstanceID, expected)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	grants := s.permissionGrants[record.PluginInstanceID]
	existing, ok := grants[strings.TrimSpace(req.PermissionID)]
	if !ok {
		return AuthorizationSnapshot{}, permissions.ErrGrantNotFound
	}
	revoked, err := permissions.Revoke(existing, req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	grants[revoked.PermissionID] = permissions.CloneRecord(revoked)
	record.PolicyRevision++
	record.RevokeEpoch++
	record.UpdatedAt = *revoked.RevokedAt
	s.records[record.PluginInstanceID] = record
	return s.authorizationSnapshotLocked(record)
}

func (s *MemoryStore) PutSecurityPolicy(_ context.Context, req security.PutPolicyRequest, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	policy, err := security.NewPolicy(req)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.requireAuthorizationMutationLocked(policy.PluginInstanceID, expected)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	s.securityPolicies[record.PluginInstanceID] = security.ClonePolicy(policy)
	record.PolicyRevision++
	record.RevokeEpoch++
	record.UpdatedAt = policy.UpdatedAt
	s.records[record.PluginInstanceID] = record
	return s.authorizationSnapshotLocked(record)
}

func (s *MemoryStore) DeleteSecurityPolicy(_ context.Context, pluginInstanceID string, now time.Time, expected AuthorizationRevisions) (AuthorizationSnapshot, error) {
	if err := security.ValidatePolicyID(pluginInstanceID); err != nil {
		return AuthorizationSnapshot{}, err
	}
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.requireAuthorizationMutationLocked(pluginInstanceID, expected)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	delete(s.securityPolicies, pluginInstanceID)
	record.PolicyRevision++
	record.RevokeEpoch++
	record.UpdatedAt = now
	s.records[pluginInstanceID] = record
	return s.authorizationSnapshotLocked(record)
}

func (s *MemoryStore) GetAuthorization(_ context.Context, pluginInstanceID string) (AuthorizationSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[strings.TrimSpace(pluginInstanceID)]
	if !ok || record.DeletedAt != nil {
		return AuthorizationSnapshot{}, ErrNotFound
	}
	return s.authorizationSnapshotLocked(record)
}

func (s *MemoryStore) ListAuthorization(_ context.Context) ([]AuthorizationSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshots := make([]AuthorizationSnapshot, 0, len(s.records))
	for _, record := range s.records {
		if record.DeletedAt != nil {
			continue
		}
		snapshot, err := s.authorizationSnapshotLocked(record)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	sortAuthorizationSnapshots(snapshots)
	return snapshots, nil
}

func (s *MemoryStore) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizationDecision, error) {
	pluginInstanceID := strings.TrimSpace(req.PluginInstanceID)
	if err := security.ValidatePolicyEvaluationRequest(security.EvaluatePolicyRequest{
		PluginInstanceID:    pluginInstanceID,
		Method:              req.Method,
		RequiredPermissions: req.PermissionIDs,
	}); err != nil {
		return AuthorizationDecision{}, err
	}

	s.mu.RLock()
	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		s.mu.RUnlock()
		return AuthorizationDecision{}, ErrNotFound
	}
	if err := ensureAuthorizationRevisions(pluginInstanceID, req.Expected, record); err != nil {
		s.mu.RUnlock()
		return AuthorizationDecision{}, err
	}
	state := authorizationStateFromRecord(record)
	requiredPermissionIDs := permissions.NormalizePermissionIDs(req.PermissionIDs)
	grantsByPermissionID := s.permissionGrants[record.PluginInstanceID]
	grants := make([]permissions.Record, 0, len(requiredPermissionIDs))
	for _, permissionID := range requiredPermissionIDs {
		if grant, ok := grantsByPermissionID[permissionID]; ok {
			grants = append(grants, permissions.CloneRecord(grant))
		}
	}
	var policy *security.PolicyRecord
	if current, ok := s.securityPolicies[record.PluginInstanceID]; ok {
		cloned := security.ClonePolicy(current)
		policy = &cloned
	}
	s.mu.RUnlock()
	return evaluateAuthorization(state, grants, policy, req)
}

func (s *MemoryStore) requireAuthorizationMutationLocked(pluginInstanceID string, expected AuthorizationRevisions) (PluginRecord, error) {
	record, ok := s.records[pluginInstanceID]
	if !ok || record.DeletedAt != nil {
		return PluginRecord{}, ErrNotFound
	}
	if err := ensureAuthorizationRevisions(pluginInstanceID, expected, record); err != nil {
		return PluginRecord{}, err
	}
	return record, nil
}

func (s *MemoryStore) authorizationSnapshotLocked(record PluginRecord) (AuthorizationSnapshot, error) {
	plugin, err := clonePluginRecord(record)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	snapshot := AuthorizationSnapshot{
		Plugin: plugin,
		Grants: clonePermissionRecordsFromMap(s.permissionGrants[record.PluginInstanceID]),
	}
	if policy, ok := s.securityPolicies[record.PluginInstanceID]; ok {
		cloned := security.ClonePolicy(policy)
		snapshot.Policy = &cloned
	}
	return snapshot, nil
}

func evaluateAuthorization(state AuthorizationState, grants []permissions.Record, policy *security.PolicyRecord, req AuthorizeRequest) (AuthorizationDecision, error) {
	policyEvaluation, err := security.Evaluate(policy, security.EvaluatePolicyRequest{
		PluginInstanceID:    state.PluginInstanceID,
		Method:              req.Method,
		RequiredPermissions: req.PermissionIDs,
	})
	if err != nil {
		return AuthorizationDecision{}, err
	}
	granted, missing, err := permissions.Evaluate(grants, permissions.CheckRequest{
		PluginInstanceID: state.PluginInstanceID,
		PermissionIDs:    req.PermissionIDs,
		Now:              req.Now,
	})
	if err != nil {
		return AuthorizationDecision{}, err
	}
	return AuthorizationDecision{
		State:              state,
		Allowed:            policyEvaluation.Allowed && granted,
		MissingPermissions: missing,
		PolicyEvaluation:   policyEvaluation,
	}, nil
}

func validateAuthorizationRevisions(expected AuthorizationRevisions) error {
	if expected.PolicyRevision == 0 || expected.ManagementRevision == 0 {
		return ErrInvalidAuthorizationRevisions
	}
	return nil
}

func ensureAuthorizationRevisions(pluginInstanceID string, expected AuthorizationRevisions, record PluginRecord) error {
	if err := validateAuthorizationRevisions(expected); err != nil {
		return err
	}
	actual := AuthorizationRevisionsFromRecord(record)
	if expected != actual {
		return &AuthorizationRevisionConflictError{
			PluginInstanceID: pluginInstanceID,
			Expected:         expected,
			Actual:           actual,
		}
	}
	return nil
}

func clonePermissionRecordsFromMap(records map[string]permissions.Record) []permissions.Record {
	cloned := make([]permissions.Record, 0, len(records))
	for _, record := range records {
		cloned = append(cloned, permissions.CloneRecord(record))
	}
	sort.Slice(cloned, func(i, j int) bool {
		return cloned[i].PermissionID < cloned[j].PermissionID
	})
	return cloned
}

func sortAuthorizationSnapshots(snapshots []AuthorizationSnapshot) {
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Plugin.PluginID == snapshots[j].Plugin.PluginID {
			return snapshots[i].Plugin.PluginInstanceID < snapshots[j].Plugin.PluginInstanceID
		}
		return snapshots[i].Plugin.PluginID < snapshots[j].Plugin.PluginID
	})
}
