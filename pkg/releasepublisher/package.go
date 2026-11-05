// Package releasepublisher inspects ordinary plugin packages for release tooling.
package releasepublisher

import (
	"context"
	"errors"
	"os"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/releaseprojection"
)

var ErrCapabilityContractsRequired = errors.New("capability contract artifacts are required")
var ErrPresentationIconOutputExists = errors.New("presentation icon output already exists")

type SecuritySummaryV1 = releaseprojection.ExternalPackageSecuritySummary

const PresentationIconEvidenceSchemaVersion = "redevplugin.presentation_icon_evidence.v1"

type PresentationIconEvidenceV1 struct {
	SchemaVersion string `json:"schema_version"`
	Path          string `json:"path"`
	MediaType     string `json:"media_type"`
	Width         int    `json:"width"`
	Height        int    `json:"height"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
}
type PackageInspection struct {
	PublisherID        string                       `json:"publisher_id"`
	PluginID           string                       `json:"plugin_id"`
	Version            string                       `json:"version"`
	PackageSHA256      string                       `json:"package_sha256"`
	EntriesSHA256      string                       `json:"entries_sha256"`
	ManifestSHA256     string                       `json:"manifest_sha256"`
	Presentation       manifest.PresentationCatalog `json:"presentation"`
	PresentationSHA256 string                       `json:"presentation_sha256"`
	PresentationIcon   *PresentationIconEvidenceV1  `json:"presentation_icon,omitempty"`
	ContractSetSHA256  string                       `json:"contract_set_sha256"`
	SecuritySummary    SecuritySummaryV1            `json:"security_summary"`
}

// InspectPackage uses the package reader and exact capability registry contracts.
func InspectPackage(ctx context.Context, filename string, contracts []capabilitycontract.KnownContract) (PackageInspection, error) {
	result, _, err := inspectPackage(ctx, filename, contracts)
	return result, err
}
func inspectPackage(ctx context.Context, filename string, contracts []capabilitycontract.KnownContract) (PackageInspection, []byte, error) {
	pkg, err := pluginpkg.ReadFile(ctx, filename, pluginpkg.DefaultReadLimits())
	if err != nil {
		return PackageInspection{}, nil, err
	}
	presentation := pkg.Manifest.PresentationCatalog()
	presentationSHA, err := manifest.PresentationCatalogSHA256(presentation)
	if err != nil {
		return PackageInspection{}, nil, err
	}
	pins := make([]capabilitycontract.Pin, 0, len(pkg.Manifest.CapabilityBindings))
	for _, binding := range pkg.Manifest.CapabilityBindings {
		pins = append(pins, binding.Contract)
	}
	summary, contractSHA, err := releaseSecuritySummary(pkg.Manifest, pins, contracts)
	if err != nil {
		return PackageInspection{}, nil, err
	}
	result := PackageInspection{PublisherID: pkg.Manifest.Publisher.PublisherID, PluginID: pkg.Manifest.PluginID(), Version: pkg.Manifest.Version(), PackageSHA256: pkg.PackageHash, EntriesSHA256: pkg.EntriesHash, ManifestSHA256: pkg.ManifestHash, Presentation: presentation, PresentationSHA256: presentationSHA, ContractSetSHA256: contractSHA, SecuritySummary: summary}
	icon, content, err := pluginpkg.ReadPresentationIcon(pkg)
	if err == nil {
		result.PresentationIcon = &PresentationIconEvidenceV1{SchemaVersion: PresentationIconEvidenceSchemaVersion, Path: icon.Path, MediaType: icon.MediaType, Width: icon.Width, Height: icon.Height, SHA256: icon.SHA256, Size: icon.Size}
	} else if !errors.Is(err, pluginpkg.ErrPresentationIconUnavailable) {
		return PackageInspection{}, nil, err
	}
	return result, content, nil
}
func ExtractPresentationIcon(ctx context.Context, filename, destination string, contracts ...capabilitycontract.KnownContract) (PresentationIconEvidenceV1, error) {
	inspected, content, err := inspectPackage(ctx, filename, contracts)
	if err != nil {
		return PresentationIconEvidenceV1{}, err
	}
	if inspected.PresentationIcon == nil {
		return PresentationIconEvidenceV1{}, pluginpkg.ErrPresentationIconUnavailable
	}
	if err := writePresentationIconNoOverwrite(destination, content); err != nil {
		return PresentationIconEvidenceV1{}, err
	}
	return *inspected.PresentationIcon, nil
}
func releaseSecuritySummary(m manifest.Manifest, pins []capabilitycontract.Pin, contracts []capabilitycontract.KnownContract) (SecuritySummaryV1, string, error) {
	if len(pins) > 0 && len(contracts) == 0 {
		return SecuritySummaryV1{}, "", ErrCapabilityContractsRequired
	}
	summary, err := releaseprojection.BuildExternalPackageSecuritySummaryFromContracts(m, contracts)
	if err != nil {
		return SecuritySummaryV1{}, "", err
	}
	contractDigest, err := releaseprojection.CapabilityContractSetSHA256(summary)
	if err != nil {
		return SecuritySummaryV1{}, "", err
	}
	return summary, contractDigest, nil
}

func writePresentationIconNoOverwrite(path string, content []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return ErrPresentationIconOutputExists
	}
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	completed = true
	return nil
}
