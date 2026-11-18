package host

import (
	"context"
	"github.com/floegence/redevplugin/v3/pkg/agentconversation"
	"github.com/floegence/redevplugin/v3/pkg/capability"
)

// ResolveDeclaredAgent returns only the role selected by this admitted call.
// Its bytes come from the verified package, never from the calling surface.
func (h *Host) ResolveDeclaredAgent(ctx context.Context, source capability.ExecutionBinding) (agentconversation.DeclaredRole, error) {
	var empty agentconversation.DeclaredRole
	if source.CapabilityID != "agent.conversation" || source.TargetMethod != agentconversation.OpenRoleMethod {
		return empty, ErrMethodRequestContract
	}
	if err := h.ValidateCapabilityContinuation(ctx, source); err != nil {
		return empty, err
	}
	record, err := h.getPluginRecord(ctx, source.PluginInstanceID)
	if err != nil {
		return empty, err
	}
	if record.ActiveFingerprint != source.ActiveFingerprint {
		return empty, ErrMethodRequestContract
	}
	if _, declared := packageEntryByPath(record.PackageEntries, agentconversation.RolesPath); !declared {
		return empty, agentconversation.ErrRoleNotDeclared
	}
	asset, err := h.readPackageAsset(ctx, record, agentconversation.RolesPath, "")
	if err != nil {
		return empty, err
	}
	roles, err := agentconversation.ParseRoles(asset.Content)
	if err != nil {
		return empty, err
	}
	id, _ := source.Target.Fields["role_id"].(string)
	role, ok := roles[id]
	if !ok {
		return empty, agentconversation.ErrRoleNotDeclared
	}
	return role, nil
}
