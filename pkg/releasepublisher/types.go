package releasepublisher

import (
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/releaseprojection"
)

const (
	ConfigSchemaVersion                   = "redevplugin.release_publisher_config.v1"
	WorkspaceSchemaVersion                = "redevplugin.release_publisher_workspace.v1"
	ReleaseRefSchemaVersion               = "redevplugin.publisher_release_ref.v1"
	PresentationIconEvidenceSchemaVersion = "redevplugin.presentation_icon_evidence.v1"
)

type PublicKeyV1 struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type ConfigV1 struct {
	SchemaVersion        string      `json:"schema_version"`
	SourceID             string      `json:"source_id"`
	Channel              string      `json:"channel"`
	SourceType           string      `json:"source_type"`
	SourceClass          string      `json:"source_class"`
	GeneratedAt          string      `json:"generated_at"`
	ExpiresAt            string      `json:"expires_at"`
	Root                 PublicKeyV1 `json:"root"`
	Signing              PublicKeyV1 `json:"signing"`
	AllowedArtifactHosts []string    `json:"allowed_artifact_hosts"`
	Distribution         string      `json:"distribution"`
}

type PackageHashSetV1 struct {
	PackageSHA256  string `json:"package_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	EntriesSHA256  string `json:"entries_sha256"`
}

type PluginReleaseRefV1 struct {
	SourceID              string           `json:"source_id"`
	Channel               string           `json:"channel"`
	ReleaseMetadataRef    string           `json:"release_metadata_ref"`
	ReleaseMetadataSHA256 string           `json:"release_metadata_sha256"`
	PublisherID           string           `json:"publisher_id"`
	PluginID              string           `json:"plugin_id"`
	Version               string           `json:"version"`
	ExpectedHashes        PackageHashSetV1 `json:"expected_hashes"`
}

type PublishedFileV1 struct {
	Locator   string `json:"locator"`
	AssetName string `json:"asset_name"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

type PublisherReleaseRefV1 struct {
	SchemaVersion string             `json:"schema_version"`
	ReleaseRef    PluginReleaseRefV1 `json:"release_ref"`
	Root          PublicKeyV1        `json:"root"`
	Files         []PublishedFileV1  `json:"files"`
}

type VerifiedOutputV1 struct {
	Presentation       manifest.PresentationCatalog `json:"presentation"`
	PresentationIcon   *PresentationIconEvidenceV1  `json:"presentation_icon,omitempty"`
	ManifestSHA256     string                       `json:"manifest_sha256"`
	PresentationSHA256 string                       `json:"presentation_sha256"`
	ContractSetSHA256  string                       `json:"contract_set_sha256"`
	SecuritySummary    SecuritySummaryV1            `json:"security_summary"`
}

// SecuritySummaryV1 aliases the Host-neutral projection so release tooling,
// markets, and install-time validation serialize one canonical shape.
type SecuritySummaryV1 = releaseprojection.ExternalPackageSecuritySummary

// PermissionSummaryV1 keeps the publisher API source-compatible while using
// the canonical Host-neutral permission projection.
type PermissionSummaryV1 = releaseprojection.ExternalPackagePermissionSummary

// PresentationIconEvidenceV1 describes exactly one verified package-local
// presentation image from a fully verified release output.
type PresentationIconEvidenceV1 struct {
	SchemaVersion string `json:"schema_version"`
	Path          string `json:"path"`
	MediaType     string `json:"media_type"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
}

type WorkspaceStatusV1 struct {
	OK              bool   `json:"ok"`
	Phase           string `json:"phase"`
	PendingRequests int    `json:"pending_requests"`
	Workspace       string `json:"workspace"`
	Output          string `json:"output,omitempty"`
}
