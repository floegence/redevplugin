package host

import (
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

func TestDevelopmentAccessIsIndependentOfInstalledGrants(t *testing.T) {
	snapshot := registry.AuthorizationSnapshot{Plugin: registry.PluginRecord{PluginInstanceID: "local", PolicyRevision: 1, ManagementRevision: 1}}
	req := registry.AuthorizeRequest{PluginInstanceID: "local", Method: "example.read", PermissionIDs: []string{"example.read"}, Expected: registry.AuthorizationRevisionsFromRecord(snapshot.Plugin)}
	check := func(h *Host, allowed bool) {
		t.Helper()
		d, err := h.evaluateMethodAccess(snapshot, req)
		if err != nil || d.Allowed != allowed {
			t.Fatalf("decision=%+v err=%v, want allowed=%v", d, err, allowed)
		}
	}
	check(&Host{}, false)
	preview := &Host{developmentAccess: map[string]bool{"example.read": true}}
	check(preview, true)
	snapshot.Policy = &security.PolicyRecord{PluginInstanceID: "local", DeniedMethods: []string{req.Method}, UpdatedAt: time.Now().UTC()}
	check(preview, false)
	snapshot.Policy = nil
	req.PermissionIDs = []string{"private.read"}
	snapshot.Grants = []permissions.Record{{PluginInstanceID: "local", PermissionID: "private.read", Effect: permissions.EffectGrant, GrantedAt: time.Now().UTC()}}
	check(&Host{}, true)
	check(preview, false)
	req.Expected.PolicyRevision++
	if _, err := preview.evaluateMethodAccess(snapshot, req); err == nil {
		t.Fatal("stale development authority admitted")
	}
}
