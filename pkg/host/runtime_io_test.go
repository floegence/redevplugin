package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/floegence/redevplugin/internal/resourceio"
	"github.com/floegence/redevplugin/pkg/sessionctx"
)

type recordingHostMountAdapter struct {
	list MountListRequest
}

func (*recordingHostMountAdapter) ResolveMount(context.Context, MountRequest) (Mount, error) {
	return Mount{}, errors.New("unexpected ResolveMount")
}

func (adapter *recordingHostMountAdapter) ListMounts(_ context.Context, request MountListRequest) ([]Mount, error) {
	adapter.list = request
	return []Mount{{ID: "workspace", Path: "/host/private/workspace", ReadOnly: false}}, nil
}

type recordingHostNetworkAdapter struct {
	request NetworkAuthorizationRequest
	err     error
}

func (adapter *recordingHostNetworkAdapter) AuthorizeNetwork(_ context.Context, request NetworkAuthorizationRequest) error {
	adapter.request = request
	return adapter.err
}

func TestHostRuntimeIOBrokerProjectsExactTrustedAdapterContext(t *testing.T) {
	mounts := &recordingHostMountAdapter{}
	networkDenied := errors.New("fixture network policy denial")
	network := &recordingHostNetworkAdapter{err: networkDenied}
	broker, err := newHostRuntimeIOBroker(normalizedAdapters{FileSystem: mounts, NetworkPolicy: network})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.closeAll() })

	invocation := resourceio.Invocation{
		Owner: resourceio.Owner{
			PluginInstanceID:   "plugini_io_projection",
			ActiveFingerprint:  "sha256:active-projection",
			Scope:              sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env-projection", OwnerUserHash: "user-projection"},
			Session:            sessionctx.SessionScope{OwnerSessionHash: "session-projection", OwnerUserHash: "user-projection", OwnerEnvHash: "env-projection", SessionChannelIDHash: "channel-projection"},
			RuntimeGeneration:  "generation-projection",
			ManagementRevision: 17,
			RevokeEpoch:        19,
			InvocationID:       "invocation-projection",
			Lifetime:           resourceio.LifetimeInvocation,
		},
		Plugin: resourceio.Plugin{ID: "com.example.projection", InstanceID: "plugini_io_projection", Version: "9.0.0"},
		Permissions: map[string]bool{
			resourceio.PermissionFSWorkspaceRead: true,
			resourceio.PermissionNetworkClient:   true,
		},
		CanRead:  true,
		CanWrite: false,
	}
	if err := broker.register(invocation.Owner.InvocationID, invocation); err != nil {
		t.Fatal(err)
	}

	mountResponse, err := broker.Control(context.Background(), invocation.Owner.InvocationID, []byte(`{"api":1,"operation":"fs.mounts","arguments":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(mountResponse) == "" || json.Valid(mountResponse) == false {
		t.Fatalf("mount response = %s", mountResponse)
	}
	if bytes.Contains(mountResponse, []byte("/host/private/workspace")) {
		t.Fatalf("mount response leaked Host path: %s", mountResponse)
	}
	assertProjectedIOContext(t, mounts.list.Session, mounts.list.Plugin)

	_, err = broker.Control(context.Background(), invocation.Owner.InvocationID, []byte(`{"api":1,"operation":"net.http.begin","arguments":{"method":"GET","url":"https://example.test:8443/data","headers":[],"redirect":"error","timeout_ms":1000}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertProjectedIOContext(t, network.request.Session, network.request.Plugin)
	if network.request.Operation != "net.http.begin" || network.request.Listen || network.request.Destination != (NetworkDestination{
		Transport: "http", Scheme: "https", Host: "example.test", Port: 8443, URL: "https://example.test:8443/data",
	}) {
		t.Fatalf("network projection = %#v", network.request)
	}
}

func assertProjectedIOContext(t *testing.T, session sessionctx.Context, plugin PluginRef) {
	t.Helper()
	if session.OwnerSessionHash != "session-projection" || session.OwnerUserHash != "user-projection" || session.OwnerEnvHash != "env-projection" || session.SessionChannelIDHash != "channel-projection" || !session.CanRead || session.CanWrite {
		t.Fatalf("session projection = %#v", session)
	}
	if plugin != (PluginRef{PluginID: "com.example.projection", PluginInstanceID: "plugini_io_projection", Version: "9.0.0", ActiveFingerprint: "sha256:active-projection"}) {
		t.Fatalf("plugin projection = %#v", plugin)
	}
}
