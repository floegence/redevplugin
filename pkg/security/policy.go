package security

import (
	"errors"
	"sort"
	"strings"
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

var (
	ErrInvalidPolicy  = errors.New("plugin security policy is invalid")
	ErrPolicyNotFound = errors.New("plugin security policy not found")
	ErrPolicyDenied   = errors.New("plugin security policy denied request")
)

func NewPolicy(req PutPolicyRequest) (PolicyRecord, error) {
	pluginInstanceID := normalizePolicyID(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return PolicyRecord{}, ErrInvalidPolicy
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	return PolicyRecord{
		PluginInstanceID:   pluginInstanceID,
		AllowedPermissions: normalizePolicyValues(req.AllowedPermissions),
		DeniedMethods:      normalizePolicyValues(req.DeniedMethods),
		UpdatedAt:          now,
	}, nil
}

func ValidatePolicy(record PolicyRecord) error {
	record = NormalizePolicy(record)
	if record.PluginInstanceID == "" || record.UpdatedAt.IsZero() {
		return ErrInvalidPolicy
	}
	return nil
}

func ValidatePolicyID(pluginInstanceID string) error {
	if normalizePolicyID(pluginInstanceID) == "" {
		return ErrInvalidPolicy
	}
	return nil
}

func ValidatePolicyEvaluationRequest(req EvaluatePolicyRequest) error {
	if normalizePolicyID(req.PluginInstanceID) == "" || normalizePolicyID(req.Method) == "" {
		return ErrInvalidPolicy
	}
	return nil
}

func Evaluate(policy *PolicyRecord, req EvaluatePolicyRequest) (PolicyEvaluation, error) {
	if err := ValidatePolicyEvaluationRequest(req); err != nil {
		return PolicyEvaluation{}, err
	}
	if policy == nil {
		return PolicyEvaluation{Allowed: true}, nil
	}
	record := NormalizePolicy(*policy)
	if err := ValidatePolicy(record); err != nil || record.PluginInstanceID != normalizePolicyID(req.PluginInstanceID) {
		return PolicyEvaluation{}, ErrInvalidPolicy
	}
	method := normalizePolicyID(req.Method)
	if _, denied := stringSet(record.DeniedMethods)[method]; denied {
		return PolicyEvaluation{
			Allowed:      false,
			Reason:       PolicyDenyReasonMethodDenied,
			DeniedMethod: method,
		}, nil
	}
	if len(record.AllowedPermissions) == 0 {
		return PolicyEvaluation{Allowed: true}, nil
	}
	allowedPermissions := stringSet(record.AllowedPermissions)
	missing := make([]string, 0)
	for _, permissionID := range normalizePolicyValues(req.RequiredPermissions) {
		if _, ok := allowedPermissions[permissionID]; !ok {
			missing = append(missing, permissionID)
		}
	}
	if len(missing) > 0 {
		return PolicyEvaluation{
			Allowed:            false,
			Reason:             PolicyDenyReasonPermissionNotAllowed,
			MissingPermissions: missing,
		}, nil
	}
	return PolicyEvaluation{Allowed: true}, nil
}

func normalizePolicyID(value string) string {
	return strings.TrimSpace(value)
}

func normalizePolicyValues(values []string) []string {
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

func NormalizePolicy(record PolicyRecord) PolicyRecord {
	record.PluginInstanceID = normalizePolicyID(record.PluginInstanceID)
	record.AllowedPermissions = normalizePolicyValues(record.AllowedPermissions)
	record.DeniedMethods = normalizePolicyValues(record.DeniedMethods)
	if !record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.UpdatedAt.UTC()
	}
	return record
}

func ClonePolicy(record PolicyRecord) PolicyRecord {
	record.AllowedPermissions = append([]string(nil), record.AllowedPermissions...)
	record.DeniedMethods = append([]string(nil), record.DeniedMethods...)
	return record
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
