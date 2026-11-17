package host

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/permissions"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

// CapabilityInspection describes admission facts, never an execution grant or
// proof that an adapter, model, resource, or business workflow will succeed.
// The snapshot is private to the authorized installation. Hosts may expose it
// through their trusted authoring UI/tools, not through an alternate plugin RPC.
type CapabilityInspection struct {
	PluginInstanceID  string                          `json:"plugin_instance_id"`
	PluginVersion     string                          `json:"plugin_version"`
	PackageSHA256     string                          `json:"package_sha256"`
	ActiveFingerprint string                          `json:"active_fingerprint"`
	Revisions         registry.AuthorizationRevisions `json:"revisions"`
	ObservedAt        time.Time                       `json:"observed_at"`
	Bindings          []CapabilityBindingInspection   `json:"bindings"`
}

type CapabilityBindingInspection struct {
	BindingID         string                       `json:"binding_id"`
	Contract          capabilitycontract.Pin       `json:"contract"`
	ContractAvailable bool                         `json:"contract_available"`
	AdapterRegistered bool                         `json:"adapter_registered"`
	OfficialView      bool                         `json:"official_view"`
	Methods           []CapabilityMethodInspection `json:"methods"`
}

type CapabilityMethodInspection struct {
	Method               string              `json:"method"`
	Declaration          manifest.MethodSpec `json:"declaration"`
	Declared             bool                `json:"declared"`
	Effect               string              `json:"effect"`
	ConfirmationRequired bool                `json:"confirmation_required"`
	RequiredPermissions  []string            `json:"required_permissions"`
	MissingPermissions   []string            `json:"missing_permissions"`
	Blockers             []string            `json:"blockers"`
}

// InspectPluginCapabilities reads one canonical authorization snapshot and the
// registered contracts. In particular, a binding does not declare its methods:
// undeclared methods are reported before permissions, without suggesting grants
// which cannot make those methods callable. No adapter is dispatched, no
// conversation/surface is created, and no grant or lifecycle state is changed.
// Invocation must still perform all normal fresh authorization and validation.
func (h *Host) InspectPluginCapabilities(ctx context.Context, req GetPermissionRequirementsRequest) (CapabilityInspection, error) {
	req.PluginInstanceID = strings.TrimSpace(req.PluginInstanceID)
	authority, err := h.authorizeManagement(ctx, ManagementActionGetPermissionRequirements,
		scopedAuthorizationCollectionTarget(ResourcePermission, sessionctx.ScopeEnvironment),
		relatedAuthorizationTargets(scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment))...)
	if err != nil {
		return CapabilityInspection{}, err
	}
	ctx, release, err := h.reserveAuthorizedAction(ctx, authority)
	if err != nil {
		return CapabilityInspection{}, err
	}
	defer release()
	if _, err := h.authorizeManagement(ctx, ManagementActionListPermissionGrants,
		scopedAuthorizationCollectionTarget(ResourcePermission, sessionctx.ScopeEnvironment),
		relatedAuthorizationTargets(scopedAuthorizationTarget(ResourcePlugin, req.PluginInstanceID, sessionctx.ScopeEnvironment))...); err != nil {
		return CapabilityInspection{}, err
	}
	if _, err := h.authorizeManagement(ctx, ManagementActionGetSecurityPolicy,
		scopedAuthorizationTarget(ResourceSecurityPolicy, req.PluginInstanceID, sessionctx.ScopeEnvironment)); err != nil {
		return CapabilityInspection{}, err
	}
	snapshot, err := h.getAuthorizationSnapshot(ctx, req.PluginInstanceID)
	if err != nil {
		return CapabilityInspection{}, err
	}
	record := snapshot.Plugin
	result := CapabilityInspection{PluginInstanceID: record.PluginInstanceID, PluginVersion: record.Version,
		PackageSHA256: record.PackageHash, ActiveFingerprint: record.ActiveFingerprint,
		Revisions: registry.AuthorizationRevisionsFromRecord(record), ObservedAt: time.Now().UTC(), Bindings: []CapabilityBindingInspection{}}
	for _, binding := range record.Manifest.CapabilityBindings {
		item := CapabilityBindingInspection{BindingID: binding.BindingID, Contract: binding.Contract, Methods: []CapabilityMethodInspection{}}
		known, failure := h.resolvePinnedCapabilityContract(record.CapabilityContracts, binding)
		if failure == nil {
			item.ContractAvailable = true
			registration, failure := h.adapters.Capabilities.Resolve(binding.Contract)
			item.AdapterRegistered = failure == nil
			item.OfficialView = failure == nil && registration.View != nil
			for _, method := range known.Contract.Methods {
				declaration := manifest.MethodSpec{Method: method.Name, Route: manifest.MethodRouteSpec{
					Kind: manifest.MethodRouteCapability, BindingID: binding.BindingID, TargetMethod: method.Name}}
				declared, exists := manifestMethod(record.Manifest, method.Name)
				view := CapabilityMethodInspection{Method: method.Name, Declaration: declaration,
					Declared: exists && declared.Route == declaration.Route, Effect: method.Effect,
					ConfirmationRequired: method.Confirmation != nil && method.Confirmation.Mode == "required",
					RequiredPermissions:  permissions.MethodGrantIDs(method.RequiredPermissions), MissingPermissions: []string{}, Blockers: []string{}}
				if !view.Declared {
					view.Blockers = append(view.Blockers, "method_not_declared")
				} else {
					decision, err := registry.EvaluateAuthorizationSnapshot(snapshot, registry.AuthorizeRequest{
						PluginInstanceID: record.PluginInstanceID, Method: method.Name, PermissionIDs: method.RequiredPermissions, Expected: result.Revisions, Now: result.ObservedAt})
					if err != nil {
						return CapabilityInspection{}, err
					}
					if len(decision.MissingPermissions) > 0 {
						view.MissingPermissions = decision.MissingPermissions
						view.Blockers = append(view.Blockers, "permission_required")
					}
					if !decision.PolicyEvaluation.Allowed {
						view.Blockers = append(view.Blockers, string(decision.PolicyEvaluation.Reason))
					}
					if record.EnableState != registry.EnableEnabled {
						view.Blockers = append(view.Blockers, "plugin_disabled")
					}
					if !registry.RunnableAuthorizationState(decision.State) {
						view.Blockers = append(view.Blockers, "execution_not_approved")
					}
					effective, err := h.effectiveMethod(record, declared)
					if err != nil {
						return CapabilityInspection{}, err
					}
					local, err := h.adapters.Policy.EvaluateLocalPolicy(ctx, authority.session, pluginRefFromRecord(record), effective)
					if err != nil {
						return CapabilityInspection{}, err
					}
					if local != PolicyAllow {
						view.Blockers = append(view.Blockers, "local_policy_denied")
					}
				}
				if !item.AdapterRegistered {
					view.Blockers = append(view.Blockers, "adapter_unavailable")
				}
				item.Methods = append(item.Methods, view)
			}
			sort.Slice(item.Methods, func(i, j int) bool { return item.Methods[i].Method < item.Methods[j].Method })
		}
		result.Bindings = append(result.Bindings, item)
	}
	sort.Slice(result.Bindings, func(i, j int) bool { return result.Bindings[i].BindingID < result.Bindings[j].BindingID })
	return result, nil
}
