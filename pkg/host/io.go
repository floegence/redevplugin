package host

import (
	"context"

	"github.com/floegence/redevplugin/pkg/sessionctx"
)

// MountRequest identifies one Host-owned filesystem mount for a trusted
// plugin invocation. Path resolution remains entirely inside the adapter.
type MountRequest struct {
	Session sessionctx.Context
	Plugin  PluginRef
	MountID string
}

type MountListRequest struct {
	Session sessionctx.Context
	Plugin  PluginRef
}

// Mount is returned only across the Host adapter boundary. Path must never be
// serialized or projected to a plugin; ReDevPlugin opens it with os.OpenRoot.
type Mount struct {
	ID       string `json:"id"`
	Path     string `json:"-"`
	ReadOnly bool   `json:"read_only"`
}

type FileSystemAdapter interface {
	ResolveMount(context.Context, MountRequest) (Mount, error)
	ListMounts(context.Context, MountListRequest) ([]Mount, error)
}

// NetworkDestination is the normalized target presented to optional Host
// policy. URL is populated for URL transports; Host, Port, Scheme, and
// Transport are populated for every transport where they apply.
type NetworkDestination struct {
	Transport string `json:"transport"`
	Scheme    string `json:"scheme,omitempty"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	URL       string `json:"url,omitempty"`
}

type NetworkAuthorizationRequest struct {
	Session     sessionctx.Context
	Plugin      PluginRef
	Operation   string
	Destination NetworkDestination
	Listen      bool
}

type NetworkPolicyAdapter interface {
	AuthorizeNetwork(context.Context, NetworkAuthorizationRequest) error
}

// IOModule supplies Host product placement and policy while ReDevPlugin owns
// resource handles, rooted filesystem operations, networking, and revocation.
type IOModule struct {
	FileSystem    FileSystemAdapter
	NetworkPolicy NetworkPolicyAdapter
}
