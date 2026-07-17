package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
)

type commandRuntimeDependencies struct {
	Path             string
	Diagnostics      observability.DiagnosticsSink
	Assets           pluginpkg.AssetStore
	SurfaceTokens    *bridge.SurfaceTokenService
	PluginData       host.PluginData
	Connectivity     connectivity.Broker
	NetworkExecutor  connectivity.NetworkExecutor
	ShardCount       int
	HandshakeTimeout time.Duration
}

func newCommandRuntimeManager(deps commandRuntimeDependencies) (runtimeclient.Manager, error) {
	if strings.TrimSpace(deps.Path) == "" {
		return nil, runtimeclient.ErrRuntimePathRequired
	}
	if deps.Diagnostics == nil {
		return nil, errors.New("runtime diagnostics sink is required")
	}
	if deps.Assets == nil {
		return nil, errors.New("runtime package asset store is required")
	}
	if deps.SurfaceTokens == nil {
		return nil, errors.New("runtime surface token service is required")
	}
	if deps.PluginData == nil {
		return nil, errors.New("runtime plugin data adapter is required")
	}
	if deps.Connectivity == nil {
		return nil, errors.New("runtime connectivity broker is required")
	}
	if deps.NetworkExecutor == nil {
		return nil, errors.New("runtime network executor is required")
	}
	return runtimeclient.NewProcessManager(runtimeclient.ProcessManagerOptions{
		ShardCount: deps.ShardCount,
		Supervisor: runtimeclient.ProcessSupervisorOptions{
			RuntimePath:      deps.Path,
			Diagnostics:      deps.Diagnostics,
			Artifacts:        commandRuntimeArtifactProvider{assets: deps.Assets},
			HandleGrants:     commandRuntimeHandleGrantValidator{tokens: deps.SurfaceTokens},
			StorageFiles:     deps.PluginData,
			StorageKV:        deps.PluginData,
			StorageSQLite:    deps.PluginData,
			Connectivity:     deps.Connectivity,
			NetworkExecutor:  deps.NetworkExecutor,
			HandshakeTimeout: deps.HandshakeTimeout,
		},
	})
}

type commandRuntimeArtifactProvider struct {
	assets pluginpkg.AssetStore
}

func (p commandRuntimeArtifactProvider) ReadArtifact(ctx context.Context, req runtimeclient.ArtifactRequest) (runtimeclient.ArtifactResult, error) {
	asset, err := p.assets.ReadAsset(ctx, req.PackageHash, req.Artifact)
	if err != nil {
		return runtimeclient.ArtifactResult{}, err
	}
	if strings.TrimSpace(asset.Entry.SHA256) == "" {
		return runtimeclient.ArtifactResult{}, fmt.Errorf("artifact %q is missing sha256", req.Artifact)
	}
	if asset.Entry.SHA256 != req.ArtifactSHA256 {
		return runtimeclient.ArtifactResult{}, fmt.Errorf("artifact %q sha256 mismatch", req.Artifact)
	}
	return runtimeclient.ArtifactResult{Content: asset.Content, SHA256: asset.Entry.SHA256}, nil
}

type commandRuntimeHandleGrantValidator struct {
	tokens *bridge.SurfaceTokenService
}

func (v commandRuntimeHandleGrantValidator) ValidateHandleGrant(_ context.Context, req runtimeclient.HandleGrantValidationRequest) (runtimeclient.HandleGrantValidationResult, error) {
	record, err := v.tokens.ValidateHandleGrant(bridge.ValidateHandleGrantRequest{
		HandleGrantToken: req.HandleGrantToken,
		Audience: bridge.Audience{
			PluginInstanceID:    req.PluginInstanceID,
			ActiveFingerprint:   req.ActiveFingerprint,
			RuntimeInstanceID:   req.RuntimeInstanceID,
			RuntimeGenerationID: req.RuntimeGenerationID,
			RuntimeShardID:      req.RuntimeShardID,
			HandleID:            req.HandleID,
			Method:              req.Method,
		},
		Revision: bridge.RevisionBinding{
			PolicyRevision:     req.PolicyRevision,
			ManagementRevision: req.ManagementRevision,
			RevokeEpoch:        req.RevokeEpoch,
		},
	})
	if err != nil {
		return runtimeclient.HandleGrantValidationResult{}, err
	}
	return runtimeclient.HandleGrantValidationResult{
		HandleGrantID:       record.TokenID,
		HandleID:            record.Audience.HandleID,
		Method:              record.Audience.Method,
		RuntimeGenerationID: record.Audience.RuntimeGenerationID,
		MaxBytesPerSecond:   record.Limits.MaxBytesPerSecond,
		MaxTotalBytes:       record.Limits.MaxTotalBytes,
	}, nil
}
