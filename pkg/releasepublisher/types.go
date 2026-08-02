package releasepublisher

import (
	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/releasecontract"
)

const (
	ConfigSchemaVersion     = "redevplugin.release_publisher_config.v1"
	WorkspaceSchemaVersion  = "redevplugin.release_publisher_workspace.v1"
	ReleaseRefSchemaVersion = "redevplugin.publisher_release_ref.v1"
)

type PublicKeyV1 struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type SigningLedgerConfigV1 struct {
	LogID string `json:"log_id"`
	PublicKeyV1
}

type ConfigV1 struct {
	SchemaVersion         string                                   `json:"schema_version"`
	SourceID              string                                   `json:"source_id"`
	Channel               string                                   `json:"channel"`
	SourceType            string                                   `json:"source_type"`
	SourceClass           string                                   `json:"source_class"`
	GeneratedAt           string                                   `json:"generated_at"`
	ExpiresAt             string                                   `json:"expires_at"`
	Root                  PublicKeyV1                              `json:"root"`
	Signing               PublicKeyV1                              `json:"signing"`
	SigningLedger         SigningLedgerConfigV1                    `json:"signing_ledger"`
	AllowedArtifactHosts  []string                                 `json:"allowed_artifact_hosts"`
	MinReDevPluginVersion string                                   `json:"min_redevplugin_version"`
	Distribution          string                                   `json:"distribution"`
	HostRequirements      []releasecontract.ReleaseHostRequirement `json:"host_requirements"`
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
	SchemaVersion string                `json:"schema_version"`
	ReleaseRef    PluginReleaseRefV1    `json:"release_ref"`
	Root          PublicKeyV1           `json:"root"`
	SigningLedger SigningLedgerConfigV1 `json:"signing_ledger"`
	Files         []PublishedFileV1     `json:"files"`
}

type VerifiedOutputV1 struct {
	Presentation       manifest.PresentationCatalog `json:"presentation"`
	ManifestSHA256     string                       `json:"manifest_sha256"`
	PresentationSHA256 string                       `json:"presentation_sha256"`
}

type WorkspaceStatusV1 struct {
	OK              bool   `json:"ok"`
	Phase           string `json:"phase"`
	PendingRequests int    `json:"pending_requests"`
	Workspace       string `json:"workspace"`
	Output          string `json:"output,omitempty"`
}
