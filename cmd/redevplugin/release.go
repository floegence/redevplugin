package main

import (
	"context"
	"os"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/releasepublisher"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

func runRelease(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "prepare":
		if len(args) != 4 {
			return usage()
		}
		configRaw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		config, err := releasepublisher.DecodeConfig(configRaw)
		if err != nil {
			return err
		}
		status, err := releasepublisher.Prepare(ctx, config, args[2], args[3])
		if err != nil {
			return err
		}
		return writeJSON(status)
	case "apply-signature":
		if len(args) != 3 {
			return usage()
		}
		response, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		status, err := releasepublisher.ApplySignature(ctx, args[1], response)
		if err != nil {
			return err
		}
		return writeJSON(status)
	case "finalize":
		if len(args) < 3 {
			return usage()
		}
		contracts, err := readCapabilityContractArtifacts(args[3:])
		if err != nil {
			return err
		}
		status, err := releasepublisher.Finalize(ctx, args[1], args[2], contracts...)
		if err != nil {
			return err
		}
		return writeJSON(status)
	case "verify":
		if len(args) < 2 {
			return usage()
		}
		contracts, err := readCapabilityContractArtifacts(args[2:])
		if err != nil {
			return err
		}
		verified, err := releasepublisher.VerifyAndInspectOutputWithContracts(ctx, args[1], contracts)
		if err != nil {
			return err
		}
		return writeJSON(presentationInspectionSummary{
			OK: true, Phase: "verified", Output: args[1], Presentation: verified.Presentation,
			PresentationIcon: verified.PresentationIcon,
			ManifestSHA256:   verified.ManifestSHA256, PresentationSHA256: verified.PresentationSHA256,
			ContractSetSHA256: verified.ContractSetSHA256, SecuritySummary: verified.SecuritySummary,
			VerifierVersion: version.CurrentPlatformVersion(),
		})
	case "extract-presentation-icon":
		if len(args) != 3 {
			return usage()
		}
		icon, err := releasepublisher.ExtractPresentationIcon(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		return writeJSON(presentationIconExtractionSummary{
			OK: true, Phase: "presentation_icon_extracted", Output: args[1], IconOutput: args[2], PresentationIcon: icon,
			VerifierVersion: version.CurrentPlatformVersion(),
		})
	default:
		return usage()
	}
}

func readCapabilityContractArtifacts(paths []string) ([]capabilitycontract.KnownContract, error) {
	contracts := make([]capabilitycontract.KnownContract, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		contract, err := capabilitycontract.NewKnownContractFromArtifact(raw)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, contract)
	}
	return contracts, nil
}
