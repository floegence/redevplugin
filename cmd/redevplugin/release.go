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
	case "inspect":
		if len(args) < 2 {
			return usage()
		}
		contracts, err := readCapabilityContractArtifacts(args[2:])
		if err != nil {
			return err
		}
		verified, err := releasepublisher.InspectPackage(ctx, args[1], contracts)
		if err != nil {
			return err
		}
		return writeJSON(verified)
	case "extract-presentation-icon":
		if len(args) < 3 {
			return usage()
		}
		contracts, err := readCapabilityContractArtifacts(args[3:])
		if err != nil {
			return err
		}
		icon, err := releasepublisher.ExtractPresentationIcon(ctx, args[1], args[2], contracts...)
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
