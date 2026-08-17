package releasecontract

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestReleaseSigningPolicyDoesNotContainCapabilityPublisherTrust(t *testing.T) {
	for _, name := range []string{"types.go", "signing.go", "decode.go", "validate.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range []string{
			"DelegatedKeyUsageHostCapabilityContract",
			"HostCapabilityContract []string",
			"CapabilityPublisherScopes",
			"SourcePolicyCapabilityPublisherScope",
		} {
			if strings.Contains(string(raw), retired) {
				t.Fatalf("%s retains retired capability publisher trust %q", name, retired)
			}
		}
	}
}

func TestReleaseMetadataDoesNotRepublishCapabilityRequirements(t *testing.T) {
	schema, err := os.ReadFile("../../spec/plugin/release-metadata.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	typesSource, err := os.ReadFile("types.go")
	if err != nil {
		t.Fatal(err)
	}
	for label, source := range map[string][]byte{"Go release contract": typesSource, "release metadata schema": schema} {
		for _, retired := range []string{"HostCapabilityContractRef", "HostCapabilityRequirementRef", "ReleaseHostRequirement", "host_capability_contract_ref", "required_capability_contracts", "host_requirements"} {
			if bytes.Contains(source, []byte(retired)) {
				t.Fatalf("%s retains release capability projection %q", label, retired)
			}
		}
	}
}

func TestSourcePolicyRejectsRetiredCapabilityPublisherFields(t *testing.T) {
	fixture := newReleaseSigningFixture(t)
	raw, err := CanonicalSourcePolicy(fixture.Policy)
	if err != nil {
		t.Fatal(err)
	}
	retired := []byte(`,"capability_publisher_scopes":[]`)
	raw = bytes.Replace(raw, []byte(`,"channel":`), append(retired, []byte(`,"channel":`)...), 1)
	if _, err := DecodeSourcePolicy(raw); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("retired capability publisher field error = %v, want ErrInvalidDocument", err)
	}
}

func TestSourcePolicyAcceptsOnlyCurrentV3(t *testing.T) {
	fixture := newReleaseSigningFixture(t)
	raw, err := CanonicalSourcePolicy(fixture.Policy)
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(raw, []byte(SourcePolicySchemaVersion), []byte("redevplugin.release_source_policy.v2"), 1)
	if _, err := DecodeSourcePolicy(legacy); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("retired source policy v2 error = %v, want ErrInvalidDocument", err)
	}
	if _, err := os.Stat("../../spec/plugin/release-source-policy-v2.schema.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired source policy v2 schema still exists: %v", err)
	}
}
