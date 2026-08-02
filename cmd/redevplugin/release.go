package main

import (
	"context"
	"os"

	"github.com/floegence/redevplugin/pkg/releasepublisher"
	"github.com/floegence/redevplugin/pkg/version"
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
		if len(args) != 3 {
			return usage()
		}
		status, err := releasepublisher.Finalize(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		return writeJSON(status)
	case "verify":
		if len(args) != 2 {
			return usage()
		}
		verified, err := releasepublisher.VerifyAndInspectOutput(ctx, args[1])
		if err != nil {
			return err
		}
		return writeJSON(presentationInspectionSummary{
			OK: true, Phase: "verified", Output: args[1], Presentation: verified.Presentation,
			ManifestSHA256: verified.ManifestSHA256, PresentationSHA256: verified.PresentationSHA256,
			ContractSetSHA256: version.CurrentCompatibilityManifest().ContractSetSHA256,
			VerifierVersion:   version.CurrentCompatibilityVersion(),
		})
	default:
		return usage()
	}
}
