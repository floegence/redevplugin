package releasepublisher

import (
	"errors"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestReleaseSecuritySummaryRequiresExactContractsForCapabilityBindings(t *testing.T) {
	m := manifest.Manifest{
		CapabilityBindings: []manifest.CapabilityBinding{{
			BindingID: "resources",
			Contract: capabilitycontract.Pin{
				PublisherID: "example.publisher", ContractID: "example.resources", ContractVersion: "1.0.0",
				ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		}},
	}
	_, _, err := releaseSecuritySummary(m, []capabilitycontract.Pin{m.CapabilityBindings[0].Contract}, nil)
	if !errors.Is(err, ErrCapabilityContractsRequired) {
		t.Fatalf("release security summary error = %v, want %v", err, ErrCapabilityContractsRequired)
	}
}
