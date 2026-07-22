package host

import (
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestValidateCapabilityArtifactFetchAllowsVerifiedHostArtifactWithoutNetworkEvidence(t *testing.T) {
	policy := releasecontract.SourcePolicyV2{SourceType: "host_artifact"}
	if err := validateCapabilityArtifactFetch(policy, nil); err != nil {
		t.Fatalf("validateCapabilityArtifactFetch(host_artifact, empty) error = %v", err)
	}
}

func TestValidateCapabilityArtifactFetchRejectsNetworkEvidenceForHostArtifact(t *testing.T) {
	policy := releasecontract.SourcePolicyV2{SourceType: "host_artifact"}
	chain := []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/schema.json", ResolvedIP: "93.184.216.34"}}
	if err := validateCapabilityArtifactFetch(policy, chain); err == nil || !strings.Contains(err.Error(), "host artifact fetch chain must be empty") {
		t.Fatalf("validateCapabilityArtifactFetch(host_artifact, network) error = %v", err)
	}
}

func TestValidateCapabilityArtifactFetchKeepsRegistryNetworkEvidenceStrict(t *testing.T) {
	policy := releasecontract.SourcePolicyV2{
		SourceType:           "registry",
		AllowedArtifactHosts: []string{"artifacts.example.com"},
	}
	if err := validateCapabilityArtifactFetch(policy, nil); err == nil {
		t.Fatal("validateCapabilityArtifactFetch(registry, empty) error = nil")
	}
	chain := []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/schema.json", ResolvedIP: "93.184.216.34"}}
	if err := validateCapabilityArtifactFetch(policy, chain); err != nil {
		t.Fatalf("validateCapabilityArtifactFetch(registry, valid) error = %v", err)
	}
}
