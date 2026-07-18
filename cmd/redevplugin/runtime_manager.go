package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/floegence/redevplugin/pkg/bridge"
	"github.com/floegence/redevplugin/pkg/connectivity"
	"github.com/floegence/redevplugin/pkg/host"
	"github.com/floegence/redevplugin/pkg/observability"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/runtimeclient"
	"github.com/floegence/redevplugin/pkg/runtimetarget"
	"github.com/floegence/redevplugin/pkg/version"
)

const (
	commandRuntimeHeartbeatInterval     = 2 * time.Second
	commandRuntimeMaxHeartbeatStaleness = 5 * time.Second
)

type commandRuntimeDependencies struct {
	Path             string
	Descriptor       runtimeclient.RuntimeDescriptor
	Diagnostics      observability.DiagnosticsSink
	Assets           pluginpkg.AssetStore
	SurfaceTokens    *bridge.SurfaceTokenService
	PluginData       host.PluginData
	Connectivity     connectivity.Broker
	NetworkExecutor  connectivity.NetworkExecutor
	ShardCount       int
	HandshakeTimeout time.Duration
}

func describeCommandRuntime(path string, target runtimetarget.Target) (runtimeclient.RuntimeDescriptor, error) {
	runtimeVersion, err := version.ParseSemVer(version.RuntimeVersion)
	if err != nil {
		return runtimeclient.RuntimeDescriptor{}, err
	}
	if err := runtimetarget.Validate(target); err != nil {
		return runtimeclient.RuntimeDescriptor{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return runtimeclient.RuntimeDescriptor{}, fmt.Errorf("open runtime artifact: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return runtimeclient.RuntimeDescriptor{}, fmt.Errorf("hash runtime artifact: %w", err)
	}
	return runtimeclient.NewRuntimeDescriptor(
		runtimeVersion,
		target,
		version.RustIPCVersion,
		version.WASMABIVersion,
		hex.EncodeToString(hasher.Sum(nil)),
	)
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
			Limits:                runtimeclient.DefaultRuntimeLimits(),
			RuntimePath:           deps.Path,
			Descriptor:            deps.Descriptor,
			Diagnostics:           deps.Diagnostics,
			Artifacts:             commandRuntimeArtifactProvider{assets: deps.Assets},
			HandleGrants:          commandRuntimeHandleGrantValidator{tokens: deps.SurfaceTokens},
			StorageFiles:          deps.PluginData,
			StorageKV:             deps.PluginData,
			StorageSQLite:         deps.PluginData,
			Connectivity:          deps.Connectivity,
			NetworkExecutor:       deps.NetworkExecutor,
			HandshakeTimeout:      deps.HandshakeTimeout,
			HeartbeatInterval:     commandRuntimeHeartbeatInterval,
			MaxHeartbeatStaleness: commandRuntimeMaxHeartbeatStaleness,
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
			PluginInstanceID:     req.PluginInstanceID,
			ActiveFingerprint:    req.ActiveFingerprint,
			RuntimeInstanceID:    req.RuntimeInstanceID,
			RuntimeGenerationID:  req.RuntimeGenerationID,
			RuntimeShardID:       req.RuntimeShardID,
			OwnerSessionHash:     req.OwnerSessionHash,
			OwnerUserHash:        req.OwnerUserHash,
			OwnerEnvHash:         req.OwnerEnvHash,
			SessionChannelIDHash: req.SessionChannelIDHash,
			HandleID:             req.HandleID,
			Method:               req.Method,
			ResourceScope:        req.ResourceScope,
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
		ResourceScope:       record.Audience.ResourceScope,
		MaxBytesPerSecond:   record.Limits.MaxBytesPerSecond,
		MaxTotalBytes:       record.Limits.MaxTotalBytes,
	}, nil
}
