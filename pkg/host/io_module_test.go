package host

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type ioTestFileSystemAdapter struct{}

func (*ioTestFileSystemAdapter) ResolveMount(_ context.Context, req MountRequest) (Mount, error) {
	return Mount{ID: req.MountID, Path: "/host/private/path"}, nil
}

func (*ioTestFileSystemAdapter) ListMounts(context.Context, MountListRequest) ([]Mount, error) {
	return []Mount{{ID: "workspace", Path: "/host/private/path"}}, nil
}

type ioTestNetworkPolicyAdapter struct{}

func (*ioTestNetworkPolicyAdapter) AuthorizeNetwork(context.Context, NetworkAuthorizationRequest) error {
	return nil
}

func TestIOModulePublicContract(t *testing.T) {
	configType := reflect.TypeFor[Config]()
	field, ok := configType.FieldByName("IO")
	if !ok || field.Type != reflect.TypeFor[*IOModule]() {
		t.Fatalf("Config.IO type = %v, want *IOModule", field.Type)
	}

	config := modularTestConfig(t)
	config.IO = &IOModule{FileSystem: &ioTestFileSystemAdapter{}}
	h, err := Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open(IO) error = %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if !h.featureConfigured(FeatureIO) {
		t.Fatal("I/O module was not configured")
	}
}

func TestIOModuleRejectsMissingAndTypedNilAdapters(t *testing.T) {
	for _, test := range []struct {
		name string
		io   *IOModule
		want string
	}{
		{name: "missing filesystem", io: &IOModule{}, want: "filesystem"},
		{name: "typed nil filesystem", io: func() *IOModule {
			var adapter *ioTestFileSystemAdapter
			return &IOModule{FileSystem: adapter}
		}(), want: "filesystem"},
		{name: "typed nil network policy", io: func() *IOModule {
			var adapter *ioTestNetworkPolicyAdapter
			return &IOModule{FileSystem: &ioTestFileSystemAdapter{}, NetworkPolicy: adapter}
		}(), want: "network policy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := modularTestConfig(t)
			config.IO = test.io
			_, err := Open(context.Background(), config)
			var configErr *HostConfigError
			if !errors.As(err, &configErr) || !errors.Is(err, ErrIOModuleRequired) || configErr.Module != string(FeatureIO) || configErr.Adapter != test.want {
				t.Fatalf("Open(IO) error = %#v, want %s %s config error", err, FeatureIO, test.want)
			}
		})
	}
}

func TestIOBoundaryKeepsPathsAndSessionCapsHostOnly(t *testing.T) {
	mountJSON, err := json.Marshal(Mount{ID: "workspace", Path: "/sensitive/host/path", ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(mountJSON) != `{"id":"workspace","read_only":true}` {
		t.Fatalf("Mount JSON = %s", mountJSON)
	}

	session := sessionctx.Context{
		OwnerSessionHash:     "session",
		OwnerUserHash:        "user",
		OwnerEnvHash:         "environment",
		SessionChannelIDHash: "channel",
		CanRead:              true,
		CanWrite:             false,
	}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{}` {
		t.Fatalf("session JSON leaks Host-only facts: %s", raw)
	}
	scope, err := session.SessionScope()
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Matches(sessionctx.SessionScope{
		OwnerSessionHash:     "session",
		OwnerUserHash:        "user",
		OwnerEnvHash:         "environment",
		SessionChannelIDHash: "channel",
	}) {
		t.Fatalf("session scope includes access caps: %#v", scope)
	}
}
