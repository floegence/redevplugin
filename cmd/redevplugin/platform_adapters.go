package main

import (
	"context"
	"errors"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
)

var (
	errCommandReleaseSourceUnavailable      = errors.New("no plugin release source is configured")
	errCommandCapabilityContractUnavailable = errors.New("no host capability contract source is configured")
	errCommandHostRequirementUnsupported    = errors.New("no matching CLI host requirement is configured")
	errCommandCoreActionUnavailable         = errors.New("no core action adapter is configured")
)

type commandReleaseSourceAdapter struct{}

func (commandReleaseSourceAdapter) ResolveReleaseSourcePolicy(context.Context, host.ReleaseSourcePolicyRequest) (host.SourcePolicySnapshot, error) {
	return host.SourcePolicySnapshot{}, errCommandReleaseSourceUnavailable
}

func (commandReleaseSourceAdapter) ResolveReleaseArtifact(context.Context, host.ReleaseArtifactResolveRequest) (host.ResolvedPackageArtifact, error) {
	return host.ResolvedPackageArtifact{}, errCommandReleaseSourceUnavailable
}

func (commandReleaseSourceAdapter) ResolveCapabilityContract(context.Context, host.CapabilityContractResolveRequest) (host.ResolvedCapabilityContractArtifact, error) {
	return host.ResolvedCapabilityContractArtifact{}, errCommandCapabilityContractUnavailable
}

func (commandReleaseSourceAdapter) ResolveCapabilityContractKey(context.Context, host.CapabilityContractKeyRequest) ([]byte, error) {
	return nil, errCommandCapabilityContractUnavailable
}

type commandHostRequirementPolicy struct{}

func (commandHostRequirementPolicy) SelectHostRequirement(_ context.Context, req host.HostRequirementSelectionRequest) (host.HostRequirementSelection, error) {
	for _, requirement := range req.Requirements {
		if requirement.HostID == "redevplugin-cli" {
			return host.HostRequirementSelection{HostID: requirement.HostID}, nil
		}
	}
	return host.HostRequirementSelection{}, errCommandHostRequirementUnsupported
}

type commandSurfaceCatalogSink struct{}

func (commandSurfaceCatalogSink) PublishSurfaces(context.Context, host.SurfaceSnapshot) error {
	return nil
}

type commandCoreActionAdapter struct{}

func (commandCoreActionAdapter) ResolveCoreActionTarget(context.Context, capability.TargetResolutionRequest) (capability.TargetDescriptor, error) {
	return capability.TargetDescriptor{}, errCommandCoreActionUnavailable
}

func (commandCoreActionAdapter) InvokeCoreAction(context.Context, capability.Invocation) (capability.Result, error) {
	return capability.Result{}, errCommandCoreActionUnavailable
}

type commandInactiveRuntimeManager struct{}

func (commandInactiveRuntimeManager) Start(context.Context, runtimeclient.Target) (runtimeclient.ManagerHealth, error) {
	return runtimeclient.ManagerHealth{}, runtimeclient.ErrRuntimeNotReady
}

func (commandInactiveRuntimeManager) Stop(context.Context) error {
	return nil
}

func (commandInactiveRuntimeManager) Health(context.Context) (runtimeclient.ManagerHealth, error) {
	return runtimeclient.ManagerHealth{Ready: false, Shards: []runtimeclient.ShardHealth{}}, nil
}

func (commandInactiveRuntimeManager) BindPlugin(context.Context, string) (runtimeclient.RuntimeBinding, error) {
	return runtimeclient.RuntimeBinding{}, runtimeclient.ErrRuntimeNotReady
}

func (commandInactiveRuntimeManager) InvokeWorker(context.Context, runtimeclient.RuntimeBinding, runtimeclient.Lease, string, []byte) ([]byte, error) {
	return nil, runtimeclient.ErrRuntimeNotReady
}

func (commandInactiveRuntimeManager) Revoke(_ context.Context, pluginInstanceID string, revokeEpoch uint64) (runtimeclient.RevokeResult, error) {
	return runtimeclient.RevokeResult{PluginInstanceID: pluginInstanceID, RevokeEpoch: revokeEpoch}, nil
}

var _ runtimeclient.Manager = commandInactiveRuntimeManager{}
