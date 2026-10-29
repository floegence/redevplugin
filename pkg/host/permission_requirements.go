package host

import (
	"fmt"
	"sort"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

type pluginMethodRequirement struct {
	method      string
	permissions []string
}

type pluginPermissionRequirementProjection struct {
	methods             []pluginMethodRequirement
	contracts           []PermissionRequirementContract
	requiredPermissions []string
}

type pinnedCapabilityContractResolver func(
	[]capabilitycontract.Pin,
	manifest.CapabilityBinding,
) (capabilitycontract.KnownContract, error)

func (h *Host) resolvePluginPermissionRequirements(record registry.PluginRecord) (pluginPermissionRequirementProjection, error) {
	return buildPluginPermissionRequirements(record, h.resolvePinnedCapabilityContract)
}

func buildPluginPermissionRequirements(
	record registry.PluginRecord,
	resolve pinnedCapabilityContractResolver,
) (pluginPermissionRequirementProjection, error) {
	bindings := make(map[string]manifest.CapabilityBinding, len(record.Manifest.CapabilityBindings))
	for _, binding := range record.Manifest.CapabilityBindings {
		bindings[binding.BindingID] = binding
	}

	contracts := make(map[capabilitycontract.Pin]capabilitycontract.KnownContract, len(bindings))
	methodsByContract := make(map[capabilitycontract.Pin]map[string]capabilitycontract.Method, len(bindings))
	contractProjections := make(map[capabilitycontract.Pin]*PermissionRequirementContract, len(bindings))
	projection := pluginPermissionRequirementProjection{
		methods:             make([]pluginMethodRequirement, 0, len(record.Manifest.Methods)),
		requiredPermissions: make([]string, 0),
	}
	for _, declared := range record.Manifest.Methods {
		var required []string
		switch declared.Route.Kind {
		case manifest.MethodRouteWorker:
			required = workerMethodPermissionIDs(record.Manifest, declared)
		case manifest.MethodRouteCapability:
			binding, ok := bindings[declared.Route.BindingID]
			if !ok {
				return pluginPermissionRequirementProjection{}, fmt.Errorf("capability binding %q is not declared", declared.Route.BindingID)
			}
			verified, ok := contracts[binding.Contract]
			if !ok {
				var err error
				verified, err = resolve(record.CapabilityContracts, binding)
				if err != nil {
					return pluginPermissionRequirementProjection{}, err
				}
				contracts[binding.Contract] = verified
				indexed := make(map[string]capabilitycontract.Method, len(verified.Contract.Methods))
				for _, method := range verified.Contract.Methods {
					indexed[method.Name] = method
				}
				methodsByContract[binding.Contract] = indexed
				contractProjections[binding.Contract] = &PermissionRequirementContract{
					ContractID:        verified.Contract.ContractID,
					ContractVersion:   verified.Contract.ContractVersion,
					ContractSHA256:    verified.Pin.ArtifactSHA256,
					CapabilityID:      verified.Contract.CapabilityID,
					CapabilityVersion: verified.Contract.CapabilityVersion,
				}
			}
			effectiveMethod, ok := methodsByContract[binding.Contract][declared.Route.TargetMethod]
			if !ok {
				return pluginPermissionRequirementProjection{}, fmt.Errorf("capability target method %q is not published", declared.Route.TargetMethod)
			}
			required = normalizeStringSet(effectiveMethod.RequiredPermissions)
			contractProjections[binding.Contract].Methods = append(
				contractProjections[binding.Contract].Methods,
				PermissionRequirementMethod{Method: declared.Method, RequiredPermissions: required},
			)
		}
		if len(required) == 0 && declared.Permissions == nil {
			continue
		}
		projection.methods = append(projection.methods, pluginMethodRequirement{method: declared.Method, permissions: required})
		projection.requiredPermissions = append(projection.requiredPermissions, required...)
	}

	projection.requiredPermissions = normalizeStringSet(projection.requiredPermissions)
	projection.contracts = make([]PermissionRequirementContract, 0, len(contractProjections))
	for _, contract := range contractProjections {
		sort.Slice(contract.Methods, func(i, j int) bool { return contract.Methods[i].Method < contract.Methods[j].Method })
		projection.contracts = append(projection.contracts, *contract)
	}
	sort.Slice(projection.contracts, func(i, j int) bool {
		if projection.contracts[i].ContractID == projection.contracts[j].ContractID {
			return projection.contracts[i].ContractVersion < projection.contracts[j].ContractVersion
		}
		return projection.contracts[i].ContractID < projection.contracts[j].ContractID
	})
	return projection, nil
}

func workerMethodPermissionIDs(value manifest.Manifest, method manifest.MethodSpec) []string {
	result := make([]string, 0)
	for _, permission := range value.WorkerPermissionIDs(method) {
		result = append(result, string(permission))
	}
	return normalizeStringSet(result)
}
