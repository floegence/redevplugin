package host

import (
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/releasecontract"
)

func TestValidateCapabilityArtifactFetchAllowsVerifiedHostArtifactWithoutNetworkEvidence(t *testing.T) {
	policy := releasecontract.SourcePolicyV2{SourceType: "registry"}
	if err := validateCapabilityArtifactFetch(policy, CapabilityArtifactOriginHost, nil); err != nil {
		t.Fatalf("validateCapabilityArtifactFetch(host_artifact, empty) error = %v", err)
	}
}

func TestValidateCapabilityArtifactFetchRejectsNetworkEvidenceForHostArtifact(t *testing.T) {
	policy := releasecontract.SourcePolicyV2{SourceType: "registry"}
	chain := []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/schema.json", ResolvedIP: "93.184.216.34"}}
	if err := validateCapabilityArtifactFetch(policy, CapabilityArtifactOriginHost, chain); err == nil || !strings.Contains(err.Error(), "host artifact fetch chain must be empty") {
		t.Fatalf("validateCapabilityArtifactFetch(host_artifact, network) error = %v", err)
	}
}

func TestValidateCapabilityArtifactFetchKeepsRegistryNetworkEvidenceStrict(t *testing.T) {
	policy := releasecontract.SourcePolicyV2{
		SourceType:           "registry",
		AllowedArtifactHosts: []string{"artifacts.example.com"},
	}
	if err := validateCapabilityArtifactFetch(policy, CapabilityArtifactOriginRegistry, nil); err == nil {
		t.Fatal("validateCapabilityArtifactFetch(registry, empty) error = nil")
	}
	chain := []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/schema.json", ResolvedIP: "93.184.216.34"}}
	if err := validateCapabilityArtifactFetch(policy, CapabilityArtifactOriginRegistry, chain); err != nil {
		t.Fatalf("validateCapabilityArtifactFetch(registry, valid) error = %v", err)
	}
}

func TestValidateCapabilityArtifactFetchRejectsMissingOrContradictoryOrigin(t *testing.T) {
	registryPolicy := releasecontract.SourcePolicyV2{
		SourceType:           "registry",
		AllowedArtifactHosts: []string{"artifacts.example.com"},
	}
	chain := []CapabilityArtifactFetchHop{{URL: "https://artifacts.example.com/schema.json", ResolvedIP: "93.184.216.34"}}
	if err := validateCapabilityArtifactFetch(registryPolicy, "", nil); err == nil || !strings.Contains(err.Error(), "origin is invalid") {
		t.Fatalf("validateCapabilityArtifactFetch(missing origin) error = %v", err)
	}
	hostPolicy := releasecontract.SourcePolicyV2{SourceType: "host_artifact"}
	if err := validateCapabilityArtifactFetch(hostPolicy, CapabilityArtifactOriginRegistry, chain); err == nil || !strings.Contains(err.Error(), "source policy") {
		t.Fatalf("validateCapabilityArtifactFetch(registry origin, host policy) error = %v", err)
	}
}
