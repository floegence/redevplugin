package agentconversation

import "testing"

func TestRolesUsePublishedProfilesAndStableKeys(t *testing.T) {
	roles, err := ParseRoles([]byte(`[{"id":"new","instructions":"","methods":[]},{"id":"rival","object_key":"table","instructions":"updated","methods":[]}]`))
	if err != nil || roles["rival"].ObjectKey != "table" || roles["new"].ObjectKey != "new" {
		t.Fatalf("roles: %+v %v", roles, err)
	}
	for _, raw := range []string{`[]`, `[{"id":"rival","instructions":"","methods":[]},{"id":"rival","instructions":"","methods":[]}]`, `[{"id":"a","id":"b","instructions":"","methods":[]}]`, `[{"id":"a","grants":true,"instructions":"","methods":[]}]`, `[{"id":"a","object_key":false,"instructions":"","methods":[]}]`} {
		if _, err := ParseRoles([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
