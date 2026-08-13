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

func TestReleaseCapabilityRequirementContainsOnlyLocalRegistryIdentity(t *testing.T) {
	typesSource, err := os.ReadFile("types.go")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../../spec/plugin/release-metadata-v8.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(typesSource, []byte("type HostCapabilityContractRef struct"))
	end := bytes.Index(typesSource[start:], []byte("type ReleaseEvidence struct"))
	if start < 0 || end < 0 {
		t.Fatal("HostCapabilityContractRef declaration was not found")
	}
	capabilityRefSource := typesSource[start : start+end]
	schemaStart := bytes.Index(schema, []byte(`"host_capability_contract_ref"`))
	schemaEnd := bytes.Index(schema[schemaStart:], []byte(`"release_evidence"`))
	if schemaStart < 0 || schemaEnd < 0 {
		t.Fatal("host_capability_contract_ref schema was not found")
	}
	capabilityRefSchema := schema[schemaStart : schemaStart+schemaEnd]
	for label, source := range map[string][]byte{"Go release contract": capabilityRefSource, "capability requirement schema": capabilityRefSchema} {
		for _, retired := range []string{
			"ArtifactRef", "ManifestRef", "ManifestSHA256", "SignatureRef", "SignatureSHA256",
			"SignatureKeyID", "SignaturePolicyEpoch", "SignatureRevocationEpoch", "CompatibilityRef",
			"CompatibilitySHA256", "GeneratedClientRef", "GeneratedClientSHA256", "NoticesRef", "NoticesSHA256",
			"artifact_ref", "manifest_ref", "manifest_sha256", "signature_ref", "signature_sha256",
			"signature_key_id", "signature_policy_epoch", "signature_revocation_epoch", "compatibility_ref",
			"compatibility_sha256", "generated_client_ref", "generated_client_sha256", "notices_ref", "notices_sha256",
		} {
			if bytes.Contains(source, []byte(retired)) {
				t.Fatalf("%s still contains remote capability publisher field %q", label, retired)
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
	fixture.PolicyInput.SchemaVersion = "redevplugin.release_source_policy.v2"
	if _, err := SourcePolicySigningPreimage(fixture.PolicyInput); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("retired source policy v2 error = %v, want ErrInvalidDocument", err)
	}
	if _, err := os.Stat("../../spec/plugin/release-source-policy-v2.schema.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired source policy v2 schema still exists: %v", err)
	}
}
