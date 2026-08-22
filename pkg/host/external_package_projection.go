package host

import (
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/releaseprojection"
	"time"
)

type ExternalPackageIntent = releaseprojection.ExternalPackageIntent
type PackageHashSet = releaseprojection.PackageHashSet
type ExternalPackageSignatureAssessment = releaseprojection.ExternalPackageSignatureAssessment
type ExternalPackageRedirectHop = releaseprojection.ExternalPackageRedirectHop
type ExternalPackageSourceProvenance = releaseprojection.ExternalPackageSourceProvenance
type ExternalPackageExecutionApproval = releaseprojection.ExternalPackageExecutionApproval
type ExternalPackageUpdateEligibility = releaseprojection.ExternalPackageUpdateEligibility
type ExternalPackageInspection struct {
	InspectionID        string                             `json:"inspection_id"`
	ExpiresAt           time.Time                          `json:"expires_at"`
	Intent              ExternalPackageIntent              `json:"intent"`
	PublisherID         string                             `json:"publisher_id"`
	PluginID            string                             `json:"plugin_id"`
	Version             string                             `json:"version"`
	Presentation        manifest.PresentationCatalog       `json:"presentation"`
	PresentationSHA256  string                             `json:"presentation_sha256"`
	InspectedHashes     PackageHashSet                     `json:"inspected_hashes"`
	SignatureAssessment ExternalPackageSignatureAssessment `json:"signature_assessment"`
	SourceProvenance    ExternalPackageSourceProvenance    `json:"source_provenance"`
	ExecutionApproval   ExternalPackageExecutionApproval   `json:"execution_approval"`
	UpdateEligibility   ExternalPackageUpdateEligibility   `json:"update_eligibility"`
	SecuritySummary     ExternalPackageSecuritySummary     `json:"security_summary"`
}

type InstalledExternalPackage struct {
	Plugin              *registry.PluginRecord              `json:"plugin"`
	SignatureAssessment *ExternalPackageSignatureAssessment `json:"signature_assessment,omitempty"`
	SourceProvenance    *ExternalPackageSourceProvenance    `json:"source_provenance,omitempty"`
	ExecutionApproval   *ExternalPackageExecutionApproval   `json:"execution_approval,omitempty"`
	UpdateEligibility   *ExternalPackageUpdateEligibility   `json:"update_eligibility,omitempty"`
	SecuritySummary     *ExternalPackageSecuritySummary     `json:"security_summary,omitempty"`
}

// The projection is owned by the host-neutral releaseprojection package so
// release publishers, markets, and Hosts cannot drift or form an import cycle.
type ExternalPackagePermissionSummary = releaseprojection.ExternalPackagePermissionSummary
type ExternalPackageMethodRouteSummary = releaseprojection.ExternalPackageMethodRouteSummary
type ExternalPackageConfirmationSummary = releaseprojection.ExternalPackageConfirmationSummary
type ExternalPackageCancelSummary = releaseprojection.ExternalPackageCancelSummary
type ExternalPackageMethodSummary = releaseprojection.ExternalPackageMethodSummary
type ExternalPackageCapabilityContractSummary = releaseprojection.ExternalPackageCapabilityContractSummary
type ExternalPackageWorkerSummary = releaseprojection.ExternalPackageWorkerSummary
type ExternalPackageNetworkMethodAccessSummary = releaseprojection.ExternalPackageNetworkMethodAccessSummary
type ExternalPackageNetworkSummary = releaseprojection.ExternalPackageNetworkSummary
type ExternalPackageStorageMethodAccessSummary = releaseprojection.ExternalPackageStorageMethodAccessSummary
type ExternalPackageStorageSummary = releaseprojection.ExternalPackageStorageSummary
type ExternalPackageSecretRefSummary = releaseprojection.ExternalPackageSecretRefSummary
type ExternalPackageCoreActionSummary = releaseprojection.ExternalPackageCoreActionSummary
type ExternalPackageIntentSummary = releaseprojection.ExternalPackageIntentSummary
type ExternalPackageSurfaceSummary = releaseprojection.ExternalPackageSurfaceSummary
type ExternalPackageSizeSummary = releaseprojection.ExternalPackageSizeSummary
type ExternalPackageSecuritySummary = releaseprojection.ExternalPackageSecuritySummary

func buildExternalPackageSecuritySummary(m manifest.Manifest, pins []capabilitycontract.Pin, required map[string][]string) (ExternalPackageSecuritySummary, error) {
	return releaseprojection.BuildExternalPackageSecuritySummary(m, pins, required)
}

func BuildExternalPackageSecuritySummary(m manifest.Manifest, pins []capabilitycontract.Pin, required map[string][]string) (ExternalPackageSecuritySummary, error) {
	return releaseprojection.BuildExternalPackageSecuritySummary(m, pins, required)
}

func CapabilityContractSetSHA256(summary ExternalPackageSecuritySummary) (string, error) {
	return releaseprojection.CapabilityContractSetSHA256(summary)
}

func externalPackageSecuritySummaryHash(summary ExternalPackageSecuritySummary) (string, error) {
	return releaseprojection.SecuritySummarySHA256(summary)
}
