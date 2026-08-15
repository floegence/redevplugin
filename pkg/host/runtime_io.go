package host

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/floegence/redevplugin/v2/internal/resourceio"
	"github.com/floegence/redevplugin/v2/pkg/sessionctx"
)

var errRuntimeIOInvocationUnknown = errors.New("runtime I/O invocation is unknown")

type hostRuntimeIOBroker struct {
	mu          sync.RWMutex
	service     *resourceio.Service
	invocations map[string]resourceio.Invocation
}

func newHostRuntimeIOBroker(adapters normalizedAdapters) (*hostRuntimeIOBroker, error) {
	table, err := resourceio.NewTableWithLimits(resourceio.DefaultLimits())
	if err != nil {
		return nil, err
	}
	var mounts resourceio.MountResolver
	if adapters.FileSystem != nil {
		mounts = hostMountResolver{adapter: adapters.FileSystem}
	}
	var network resourceio.NetworkAuthorizer
	if adapters.NetworkPolicy != nil {
		network = hostNetworkAuthorizer{adapter: adapters.NetworkPolicy}
	}
	service, err := resourceio.NewService(table, mounts, network)
	if err != nil {
		return nil, err
	}
	return &hostRuntimeIOBroker{service: service, invocations: map[string]resourceio.Invocation{}}, nil
}

func (broker *hostRuntimeIOBroker) register(invocationID string, invocation resourceio.Invocation) error {
	invocationID = strings.TrimSpace(invocationID)
	if broker == nil || broker.service == nil || invocationID == "" || invocation.Owner.InvocationID != invocationID {
		return errRuntimeIOInvocationUnknown
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if _, exists := broker.invocations[invocationID]; exists {
		return errRuntimeIOInvocationUnknown
	}
	broker.invocations[invocationID] = invocation
	return nil
}

func (broker *hostRuntimeIOBroker) release(invocationID string) error {
	if broker == nil || broker.service == nil {
		return nil
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	invocation, exists := broker.invocations[invocationID]
	delete(broker.invocations, invocationID)
	if !exists {
		return nil
	}
	return broker.service.Revoke(func(owner resourceio.Owner) bool {
		return owner.Lifetime == resourceio.LifetimeInvocation && owner.InvocationID == invocation.Owner.InvocationID
	})
}

func (broker *hostRuntimeIOBroker) invocationLocked(invocationID string) (resourceio.Invocation, error) {
	if broker == nil || broker.service == nil || strings.TrimSpace(invocationID) == "" {
		return resourceio.Invocation{}, errRuntimeIOInvocationUnknown
	}
	invocation, ok := broker.invocations[invocationID]
	if !ok {
		return resourceio.Invocation{}, errRuntimeIOInvocationUnknown
	}
	return invocation, nil
}

func (broker *hostRuntimeIOBroker) Control(ctx context.Context, invocationID string, raw []byte) ([]byte, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return nil, err
	}
	return broker.service.Control(ctx, invocation, raw)
}

func (broker *hostRuntimeIOBroker) Read(ctx context.Context, invocationID string, handle uint64, destination []byte) (int, uint32, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return 0, 0, err
	}
	return broker.service.Read(ctx, invocation, handle, destination)
}

func (broker *hostRuntimeIOBroker) Write(ctx context.Context, invocationID string, handle uint64, source []byte, flags uint32) (int, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return 0, err
	}
	return broker.service.Write(ctx, invocation, handle, source, flags)
}

func (broker *hostRuntimeIOBroker) Seek(_ context.Context, invocationID string, handle uint64, offset int64, whence int) (int64, error) {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return 0, err
	}
	return broker.service.Seek(invocation, handle, offset, whence)
}

func (broker *hostRuntimeIOBroker) Close(_ context.Context, invocationID string, handle uint64) error {
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	invocation, err := broker.invocationLocked(invocationID)
	if err != nil {
		return err
	}
	return broker.service.Close(invocation, handle)
}

func (broker *hostRuntimeIOBroker) closeAll() error {
	if broker == nil || broker.service == nil {
		return nil
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	clear(broker.invocations)
	return broker.service.Revoke(func(resourceio.Owner) bool { return true })
}

func (broker *hostRuntimeIOBroker) revokePlugin(ownerEnvHash, pluginInstanceID string) error {
	if broker == nil || broker.service == nil {
		return nil
	}
	ownerEnvHash = strings.TrimSpace(ownerEnvHash)
	pluginInstanceID = strings.TrimSpace(pluginInstanceID)
	if ownerEnvHash == "" || pluginInstanceID == "" {
		return errRuntimeIOInvocationUnknown
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	for invocationID, invocation := range broker.invocations {
		if invocation.Owner.PluginInstanceID == pluginInstanceID && invocation.Owner.Scope.OwnerEnvHash == ownerEnvHash {
			delete(broker.invocations, invocationID)
		}
	}
	return broker.service.Revoke(func(owner resourceio.Owner) bool {
		return owner.PluginInstanceID == pluginInstanceID && owner.Scope.OwnerEnvHash == ownerEnvHash
	})
}

func (broker *hostRuntimeIOBroker) revokeSession(scope sessionctx.SessionScope) error {
	if broker == nil || broker.service == nil {
		return nil
	}
	if !scope.Valid() {
		return errRuntimeIOInvocationUnknown
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	for invocationID, invocation := range broker.invocations {
		if invocation.Owner.Session.Matches(scope) {
			delete(broker.invocations, invocationID)
		}
	}
	return broker.service.Revoke(func(owner resourceio.Owner) bool { return owner.Session.Matches(scope) })
}

type hostMountResolver struct {
	adapter FileSystemAdapter
}

func (resolver hostMountResolver) ResolveMount(ctx context.Context, invocation resourceio.Invocation, mountID string) (resourceio.MountSpec, error) {
	mount, err := resolver.adapter.ResolveMount(ctx, MountRequest{
		Session: resourceInvocationSession(invocation),
		Plugin:  resourceInvocationPlugin(invocation),
		MountID: mountID,
	})
	if err != nil {
		return resourceio.MountSpec{}, mapMountAdapterError(err)
	}
	return resourceio.MountSpec{ID: mount.ID, Path: mount.Path, ReadOnly: mount.ReadOnly}, nil
}

func (resolver hostMountResolver) ListMounts(ctx context.Context, invocation resourceio.Invocation) ([]resourceio.MountSpec, error) {
	mounts, err := resolver.adapter.ListMounts(ctx, MountListRequest{
		Session: resourceInvocationSession(invocation),
		Plugin:  resourceInvocationPlugin(invocation),
	})
	if err != nil {
		return nil, mapMountAdapterError(err)
	}
	result := make([]resourceio.MountSpec, len(mounts))
	for index, mount := range mounts {
		result[index] = resourceio.MountSpec{ID: mount.ID, Path: mount.Path, ReadOnly: mount.ReadOnly}
	}
	return result, nil
}

func mapMountAdapterError(err error) error {
	if errors.Is(err, ErrMountUnavailable) {
		return resourceio.ErrMountUnavailable
	}
	return err
}

type hostNetworkAuthorizer struct {
	adapter NetworkPolicyAdapter
}

func (authorizer hostNetworkAuthorizer) AuthorizeNetwork(ctx context.Context, request resourceio.NetworkAuthorization) error {
	return authorizer.adapter.AuthorizeNetwork(ctx, NetworkAuthorizationRequest{
		Session:     resourceInvocationSession(request.Invocation),
		Plugin:      resourceInvocationPlugin(request.Invocation),
		Operation:   request.Operation,
		Destination: publicNetworkDestination(request.Destination),
		Listen:      request.Listen,
	})
}

func resourceInvocationSession(invocation resourceio.Invocation) sessionctx.Context {
	return sessionctx.Context{
		OwnerSessionHash:     invocation.Owner.Session.OwnerSessionHash,
		OwnerUserHash:        invocation.Owner.Session.OwnerUserHash,
		OwnerEnvHash:         invocation.Owner.Session.OwnerEnvHash,
		SessionChannelIDHash: invocation.Owner.Session.SessionChannelIDHash,
		CanRead:              invocation.CanRead,
		CanWrite:             invocation.CanWrite,
	}
}

func resourceInvocationPlugin(invocation resourceio.Invocation) PluginRef {
	return PluginRef{
		PluginID:          invocation.Plugin.ID,
		PluginInstanceID:  invocation.Plugin.InstanceID,
		Version:           invocation.Plugin.Version,
		ActiveFingerprint: invocation.Owner.ActiveFingerprint,
	}
}

func publicNetworkDestination(destination *url.URL) NetworkDestination {
	if destination == nil {
		return NetworkDestination{}
	}
	port := 0
	if rawPort := destination.Port(); rawPort != "" {
		port, _ = strconv.Atoi(rawPort)
	} else {
		switch destination.Scheme {
		case "http", "ws":
			port = 80
		case "https", "wss":
			port = 443
		}
	}
	transport := destination.Scheme
	switch destination.Scheme {
	case "http", "https":
		transport = "http"
	case "ws", "wss":
		transport = "websocket"
	}
	return NetworkDestination{
		Transport: transport,
		Scheme:    destination.Scheme,
		Host:      destination.Hostname(),
		Port:      port,
		URL:       destination.String(),
	}
}
