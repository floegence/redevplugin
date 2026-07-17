package permissions

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNewGrantNormalizesRecord(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.FixedZone("test", 3600))
	expiresAt := now.Add(time.Hour)
	record, err := NewGrant(GrantRequest{
		PluginInstanceID: " plugin_a ",
		PermissionID:     " resources.read ",
		GrantedBy:        " user_a ",
		Now:              now,
		ExpiresAt:        expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.PluginInstanceID != "plugin_a" || record.PermissionID != "resources.read" || record.GrantedBy != "user_a" || record.Effect != EffectGrant {
		t.Fatalf("NewGrant() = %#v", record)
	}
	if !record.GrantedAt.Equal(now) || record.GrantedAt.Location() != time.UTC || record.ExpiresAt == nil || record.ExpiresAt.Location() != time.UTC {
		t.Fatalf("NewGrant() times = %#v", record)
	}
}

func TestEvaluateGrants(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	active, err := NewGrant(GrantRequest{PluginInstanceID: "plugin_a", PermissionID: "resources.read", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := NewGrant(GrantRequest{PluginInstanceID: "plugin_a", PermissionID: "resources.write", Now: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	granted, missing, err := Evaluate([]Record{expired, active}, CheckRequest{
		PluginInstanceID: " plugin_a ",
		PermissionIDs:    []string{"resources.read", "resources.read"},
		Now:              now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !granted || len(missing) != 0 {
		t.Fatalf("Evaluate(active) = %v, %v", granted, missing)
	}
	granted, missing, err = Evaluate([]Record{expired, active}, CheckRequest{
		PluginInstanceID: "plugin_a",
		PermissionIDs:    []string{"resources.write", "resources.delete", "resources.delete"},
		Now:              now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if granted || !reflect.DeepEqual(missing, []string{"resources.delete", "resources.write"}) {
		t.Fatalf("Evaluate(missing) = %v, %v", granted, missing)
	}
}

func TestRevokeGrant(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	record, err := NewGrant(GrantRequest{PluginInstanceID: "plugin_a", PermissionID: "resources.read", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := Revoke(record, RevokeRequest{
		PluginInstanceID: " plugin_a ",
		PermissionID:     " resources.read ",
		RevokedBy:        " admin ",
		Reason:           " review ",
		Now:              now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(now.Add(time.Minute)) || revoked.RevokedBy != "admin" || revoked.RevokedReason != "review" || Active(revoked, now.Add(2*time.Minute)) {
		t.Fatalf("Revoke() = %#v", revoked)
	}
	if record.RevokedAt != nil {
		t.Fatalf("Revoke() mutated input: %#v", record)
	}
}

func TestPermissionFunctionsRejectInvalidInput(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	if _, err := NewGrant(GrantRequest{PluginInstanceID: "plugin_a", Now: now}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := ValidateRecord(Record{PluginInstanceID: "plugin_a", PermissionID: "read", Effect: "unknown", GrantedAt: now}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("ValidateRecord() error = %v", err)
	}
	if _, _, err := Evaluate(nil, CheckRequest{PermissionIDs: []string{"read"}, Now: now}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("Evaluate() error = %v", err)
	}
	valid, err := NewGrant(GrantRequest{PluginInstanceID: "plugin_a", PermissionID: "read", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(valid, RevokeRequest{PluginInstanceID: "plugin_a", PermissionID: "missing", Now: now}); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, _, err := Evaluate([]Record{{PluginInstanceID: "plugin_b", PermissionID: "read", Effect: EffectGrant, GrantedAt: now}}, CheckRequest{PluginInstanceID: "plugin_a", PermissionIDs: []string{"read"}, Now: now}); !errors.Is(err, ErrInvalidPermission) {
		t.Fatalf("Evaluate(mixed plugin) error = %v", err)
	}
}

func TestCloneRecordDoesNotShareTimePointers(t *testing.T) {
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	revokedAt := now.Add(time.Minute)
	record := Record{ExpiresAt: &expiresAt, RevokedAt: &revokedAt}
	cloned := CloneRecord(record)
	*cloned.ExpiresAt = now.Add(2 * time.Hour)
	*cloned.RevokedAt = now.Add(2 * time.Minute)
	if !record.ExpiresAt.Equal(expiresAt) || !record.RevokedAt.Equal(revokedAt) {
		t.Fatalf("CloneRecord() shared pointers: original=%#v clone=%#v", record, cloned)
	}
}
