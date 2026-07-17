package permissions

import (
	"errors"
	"sort"
	"strings"
	"time"
)

type Effect string

const (
	EffectGrant Effect = "grant"
	EffectDeny  Effect = "deny"
)

type Record struct {
	PluginInstanceID string     `json:"plugin_instance_id"`
	PermissionID     string     `json:"permission_id"`
	Effect           Effect     `json:"effect"`
	GrantedBy        string     `json:"granted_by,omitempty"`
	GrantedAt        time.Time  `json:"granted_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevokedReason    string     `json:"revoked_reason,omitempty"`
}

type GrantRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	GrantedBy        string    `json:"granted_by,omitempty"`
	Now              time.Time `json:"now,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type RevokeRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionID     string    `json:"permission_id"`
	RevokedBy        string    `json:"revoked_by,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Now              time.Time `json:"now,omitempty"`
}

type CheckRequest struct {
	PluginInstanceID string    `json:"plugin_instance_id"`
	PermissionIDs    []string  `json:"permission_ids"`
	Now              time.Time `json:"now,omitempty"`
}

var (
	ErrInvalidPermission = errors.New("permission grant is invalid")
	ErrPermissionDenied  = errors.New("plugin permission grant is required")
	ErrGrantNotFound     = errors.New("permission grant not found")
)

func NewGrant(req GrantRequest) (Record, error) {
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	permissionID := normalizeID(req.PermissionID)
	if pluginInstanceID == "" || permissionID == "" {
		return Record{}, ErrInvalidPermission
	}
	now := normalizeNow(req.Now)
	record := Record{
		PluginInstanceID: pluginInstanceID,
		PermissionID:     permissionID,
		Effect:           EffectGrant,
		GrantedBy:        normalizeID(req.GrantedBy),
		GrantedAt:        now,
	}
	if !req.ExpiresAt.IsZero() {
		expiresAt := req.ExpiresAt.UTC()
		record.ExpiresAt = &expiresAt
	}
	return record, nil
}

func ValidateRecord(record Record) error {
	record = NormalizeRecord(record)
	if record.PluginInstanceID == "" || record.PermissionID == "" || record.GrantedAt.IsZero() {
		return ErrInvalidPermission
	}
	if record.Effect != EffectGrant && record.Effect != EffectDeny {
		return ErrInvalidPermission
	}
	return nil
}

func ValidateRevokeRequest(req RevokeRequest) error {
	if normalizeID(req.PluginInstanceID) == "" || normalizeID(req.PermissionID) == "" {
		return ErrInvalidPermission
	}
	return nil
}

func Evaluate(records []Record, req CheckRequest) (bool, []string, error) {
	pluginInstanceID := normalizeID(req.PluginInstanceID)
	if pluginInstanceID == "" {
		return false, nil, ErrInvalidPermission
	}
	required := NormalizePermissionIDs(req.PermissionIDs)
	if len(required) == 0 {
		return true, nil, nil
	}
	byPermissionID := make(map[string]Record, len(records))
	for _, record := range records {
		record = NormalizeRecord(record)
		if err := ValidateRecord(record); err != nil || record.PluginInstanceID != pluginInstanceID {
			return false, nil, ErrInvalidPermission
		}
		if _, exists := byPermissionID[record.PermissionID]; exists {
			return false, nil, ErrInvalidPermission
		}
		byPermissionID[record.PermissionID] = record
	}
	now := normalizeNow(req.Now)
	missing := make([]string, 0)
	for _, permissionID := range required {
		record, ok := byPermissionID[permissionID]
		if !ok || !Active(record, now) {
			missing = append(missing, permissionID)
		}
	}
	return len(missing) == 0, missing, nil
}

func Revoke(record Record, req RevokeRequest) (Record, error) {
	if err := ValidateRevokeRequest(req); err != nil {
		return Record{}, err
	}
	record = NormalizeRecord(record)
	if err := ValidateRecord(record); err != nil {
		return Record{}, err
	}
	if record.PluginInstanceID != normalizeID(req.PluginInstanceID) || record.PermissionID != normalizeID(req.PermissionID) {
		return Record{}, ErrGrantNotFound
	}
	revokedAt := normalizeNow(req.Now)
	record.RevokedAt = &revokedAt
	record.RevokedBy = normalizeID(req.RevokedBy)
	record.RevokedReason = strings.TrimSpace(req.Reason)
	return record, nil
}

func Active(record Record, now time.Time) bool {
	if record.Effect != EffectGrant || record.RevokedAt != nil {
		return false
	}
	now = normalizeNow(now)
	return record.ExpiresAt == nil || record.ExpiresAt.After(now)
}

func normalizeID(value string) string {
	return strings.TrimSpace(value)
}

func NormalizePermissionIDs(permissionIDs []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		permissionID = normalizeID(permissionID)
		if permissionID == "" {
			continue
		}
		if _, ok := seen[permissionID]; ok {
			continue
		}
		seen[permissionID] = struct{}{}
		normalized = append(normalized, permissionID)
	}
	sort.Strings(normalized)
	return normalized
}

func NormalizeRecord(record Record) Record {
	record.PluginInstanceID = normalizeID(record.PluginInstanceID)
	record.PermissionID = normalizeID(record.PermissionID)
	record.GrantedBy = normalizeID(record.GrantedBy)
	record.RevokedBy = normalizeID(record.RevokedBy)
	record.RevokedReason = strings.TrimSpace(record.RevokedReason)
	if !record.GrantedAt.IsZero() {
		record.GrantedAt = record.GrantedAt.UTC()
	}
	if record.ExpiresAt != nil {
		expiresAt := record.ExpiresAt.UTC()
		record.ExpiresAt = &expiresAt
	}
	if record.RevokedAt != nil {
		revokedAt := record.RevokedAt.UTC()
		record.RevokedAt = &revokedAt
	}
	return record
}

func CloneRecord(record Record) Record {
	if record.ExpiresAt != nil {
		expiresAt := *record.ExpiresAt
		record.ExpiresAt = &expiresAt
	}
	if record.RevokedAt != nil {
		revokedAt := *record.RevokedAt
		record.RevokedAt = &revokedAt
	}
	return record
}

func normalizeNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}
