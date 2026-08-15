package manifest

import "errors"

const SchemaVersionV9 = "redevplugin.manifest.v9"

type FeatureID string
type PermissionID string

const (
	FeatureIOStream      FeatureID = "io.stream.v1"
	FeatureFSWorkspace   FeatureID = "fs.workspace.v1"
	FeatureFSHome        FeatureID = "fs.home.v1"
	FeatureFSEnvironment FeatureID = "fs.environment.v1"
	FeatureFSWatch       FeatureID = "fs.watch.v1"
	FeatureNetHTTP       FeatureID = "net.http.v1"
	FeatureNetWebSocket  FeatureID = "net.websocket.v1"
	FeatureNetTCP        FeatureID = "net.tcp.v1"
	FeatureNetUDP        FeatureID = "net.udp.v1"
)

const (
	PermissionFSWorkspaceRead    PermissionID = "fs.workspace.read"
	PermissionFSWorkspaceWrite   PermissionID = "fs.workspace.write"
	PermissionFSHomeRead         PermissionID = "fs.home.read"
	PermissionFSHomeWrite        PermissionID = "fs.home.write"
	PermissionFSEnvironmentRead  PermissionID = "fs.environment.read"
	PermissionFSEnvironmentWrite PermissionID = "fs.environment.write"
	PermissionNetworkClient      PermissionID = "network.client"
	PermissionNetworkListen      PermissionID = "network.listen"
)

var ErrUnsupportedFeature = errors.New("UNSUPPORTED_FEATURE")
var ErrUnsupportedPermission = errors.New("UNSUPPORTED_PERMISSION")

type PublicAPIRequirement struct {
	Surface          *uint16     `json:"surface,omitempty"`
	Worker           *uint16     `json:"worker,omitempty"`
	RequiredFeatures []FeatureID `json:"required_features,omitempty"`
	OptionalFeatures []FeatureID `json:"optional_features,omitempty"`
}

// Model is the single normalized manifest representation consumed after the
// decode boundary. Manifest is embedded for source compatibility while
// downstream packages migrate away from schema-specific fields.
type Model struct {
	Manifest
	SchemaSource string
	API          PublicAPIRequirement
	Permissions  []PermissionID
}

func (m Model) RequiredFeatureIDs() []FeatureID {
	return append([]FeatureID(nil), m.API.RequiredFeatures...)
}

func (m Model) OptionalFeatureIDs() []FeatureID {
	return append([]FeatureID(nil), m.API.OptionalFeatures...)
}

func (m Model) PermissionIDs() []PermissionID {
	return append([]PermissionID(nil), m.Permissions...)
}
