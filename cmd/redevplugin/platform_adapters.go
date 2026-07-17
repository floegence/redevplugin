package main

import (
	"context"
	"errors"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/host"
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
