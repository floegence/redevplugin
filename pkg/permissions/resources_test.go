package permissions

import (
	"reflect"
	"testing"
)

func TestResourceCeilingsCannotBecomeBooleanGrants(t *testing.T) {
	for _, id := range []string{"fs.selected.read", "fs.selected.write"} {
		if _, err := NewGrant(GrantRequest{PluginInstanceID: "plugin", PermissionID: id}); err == nil {
			t.Fatalf("boolean grant accepted %s", id)
		}
	}
	got := MethodGrantIDs([]string{"fs.selected.read", "network.client", "fs.selected.write"})
	if !reflect.DeepEqual(got, []string{"network.client"}) {
		t.Fatalf("method grant IDs=%v", got)
	}
}
