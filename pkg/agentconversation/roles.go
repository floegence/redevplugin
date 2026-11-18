package agentconversation

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"

	"github.com/floegence/redevplugin/v3/internal/canonicaljson"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
)

const RolesPath = "agents.json"
const OpenRoleMethod = "agent.conversation.role.open"

var ErrRoleNotDeclared = errors.New("agent role is not declared in the active package")

// DeclaredRole uses the published profile schema. ObjectKey defaults to the
// profile ID; an existing plugin can explicitly keep its original binding key.
type DeclaredRole struct {
	ObjectKey string
	Profile   json.RawMessage
}

var profileSchema = sync.OnceValues(func() (map[string]any, error) {
	k, err := Contract()
	if err != nil {
		return nil, err
	}
	for _, m := range k.Contract.Methods {
		if m.Name == "agent.conversation.bind" {
			return m.RequestSchema["properties"].(map[string]any)["profile"].(map[string]any), nil
		}
	}
	return nil, errors.New("missing Agent profile schema")
})

// ParseRoles is shared by package validation and exact-package resolution.
func ParseRoles(content []byte) (map[string]DeclaredRole, error) {
	if len(content) > 1<<20 {
		return nil, errors.New("agents.json exceeds 1 MiB")
	}
	canonical, err := canonicaljson.CanonicalJSON(content)
	if err != nil {
		return nil, err
	}
	var list []map[string]any
	if err := json.Unmarshal(canonical, &list); err != nil || len(list) == 0 || len(list) > 64 {
		return nil, errors.New("agents.json must contain 1 to 64 profiles")
	}
	schema, err := profileSchema()
	if err != nil {
		return nil, err
	}
	result := make(map[string]DeclaredRole, len(list))
	for i, profile := range list {
		key, explicit := profile["object_key"]
		delete(profile, "object_key")
		if err := capabilitycontract.ValidateValue(schema, profile); err != nil {
			return nil, fmt.Errorf("agents.json[%d]: %w", i, err)
		}
		id := profile["id"].(string)
		objectKey := id
		if explicit {
			var ok bool
			objectKey, ok = key.(string)
			if !ok || objectKey == "" || utf8.RuneCountInString(objectKey) > 512 {
				return nil, fmt.Errorf("agents.json[%d]: invalid object_key", i)
			}
		}
		if _, exists := result[id]; exists {
			return nil, fmt.Errorf("agents.json[%d]: duplicate role id %q", i, id)
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			return nil, err
		}
		result[id] = DeclaredRole{ObjectKey: objectKey, Profile: raw}
	}
	return result, nil
}
