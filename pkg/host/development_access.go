package host

import (
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/security"
)

// Callers supply the permissions resolved by the host from a declared method,
// never permission names from plugin arguments. Resource selection, session,
// policy and confirmation remain separate checks.
func (h *Host) checkAccess(snapshot registry.AuthorizationSnapshot, required []string) (bool, []string, error) {
	if h.developmentAccess != nil {
		for _, id := range required {
			if !h.developmentAccess[id] {
				return false, nil, security.ErrPolicyDenied
			}
		}
		return true, nil, nil
	}
	return permissions.Evaluate(snapshot.Grants, permissions.CheckRequest{PluginInstanceID: snapshot.Plugin.PluginInstanceID, PermissionIDs: permissions.MethodGrantIDs(required)})
}

func (h *Host) evaluateMethodAccess(snapshot registry.AuthorizationSnapshot, req registry.AuthorizeRequest) (registry.AuthorizationDecision, error) {
	if h.developmentAccess != nil {
		return registry.EvaluateDevelopmentAuthorization(snapshot, req, h.developmentAccess)
	}
	return registry.EvaluateAuthorizationSnapshot(snapshot, req)
}
