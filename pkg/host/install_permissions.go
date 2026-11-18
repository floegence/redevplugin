package host

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func normalizeInstallPermissions(ids []string) ([]string, error) {
	if len(ids) > 128 {
		return nil, ErrExternalPackageRequestInvalid
	}
	result := slices.Clone(ids)
	slices.Sort(result)
	for i, id := range result {
		if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || permissions.ResourceScoped(id) || i > 0 && result[i-1] == id {
			return nil, ErrExternalPackageRequestInvalid
		}
	}
	return result, nil
}

// Discovery is a current management observation, never a grant or execution
// certificate. Resource ceilings keep their separate exact-resource review.
func (h *Host) inspectGrantablePermissions(ctx context.Context, session sessionctx.Context, instance string, summary ExternalPackageSecuritySummary) ([]string, error) {
	result := make([]string, 0)
	for _, permission := range summary.Permissions {
		if permissions.ResourceScoped(permission.PermissionID) {
			continue
		}
		if _, err := h.authorizeManagementSession(ctx, session, ManagementActionGrantPermission,
			scopedAuthorizationTarget(ResourcePermission, permission.PermissionID, sessionctx.ScopeEnvironment),
			scopedAuthorizationTarget(ResourcePlugin, instance, sessionctx.ScopeEnvironment)); err == nil {
			result = append(result, permission.PermissionID)
		} else if !errors.Is(err, ErrActionDenied) {
			return nil, err
		}
	}
	return result, nil
}

func (h *Host) reviewedInstallGrants(ctx context.Context, session sessionctx.Context, inspection ExternalPackageInspection, approved []string, now time.Time) ([]permissions.Record, error) {
	ids, err := normalizeInstallPermissions(approved)
	if err != nil {
		return nil, err
	}
	grants := make([]permissions.Record, 0, len(ids))
	for _, id := range ids {
		if !slices.Contains(inspection.GrantablePermissions, id) {
			return nil, ErrExternalPackageConfirmation
		}
		if _, err := h.authorizeManagementSession(ctx, session, ManagementActionGrantPermission,
			scopedAuthorizationTarget(ResourcePermission, id, sessionctx.ScopeEnvironment),
			scopedAuthorizationTarget(ResourcePlugin, inspection.Intent.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
			return nil, err
		}
		grant, err := permissions.NewGrant(permissions.GrantRequest{PluginInstanceID: inspection.Intent.PluginInstanceID, PermissionID: id, GrantedBy: session.OwnerUserHash, Now: now})
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, nil
}
