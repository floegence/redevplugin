package protocol

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/releasecontract"
	"github.com/floegence/redevplugin/pkg/releasepublisher"
)

func TestReleasePublisherSchemasMatchGoWireDTOs(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		topLevel   reflect.Type
		nestedDefs map[string]reflect.Type
	}{
		{
			name:     "release-publisher-config-v1.schema.json",
			topLevel: reflect.TypeOf(releasepublisher.ConfigV1{}),
			nestedDefs: map[string]reflect.Type{
				"public_key":             reflect.TypeOf(releasepublisher.PublicKeyV1{}),
				"signing_ledger":         reflect.TypeOf(releasepublisher.SigningLedgerConfigV1{}),
				"host_requirement":       reflect.TypeOf(releasecontract.ReleaseHostRequirement{}),
				"capability_requirement": reflect.TypeOf(releasecontract.HostCapabilityRequirementRef{}),
			},
		},
		{
			name:     "publisher-release-ref-v1.schema.json",
			topLevel: reflect.TypeOf(releasepublisher.PublisherReleaseRefV1{}),
			nestedDefs: map[string]reflect.Type{
				"release_ref":    reflect.TypeOf(releasepublisher.PluginReleaseRefV1{}),
				"public_key":     reflect.TypeOf(releasepublisher.PublicKeyV1{}),
				"signing_ledger": reflect.TypeOf(releasepublisher.SigningLedgerConfigV1{}),
				"hash_set":       reflect.TypeOf(releasepublisher.PackageHashSetV1{}),
				"published_file": reflect.TypeOf(releasepublisher.PublishedFileV1{}),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(repoRoot(t), "spec", "plugin", testCase.name))
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			assertStringSet(t, objectKeys(requireNestedObject(t, schema, "properties")), publisherJSONFields(t, testCase.topLevel), "top-level publisher properties")
			assertStringSet(t, requireStringSlice(t, schema["required"], "top-level publisher required"), publisherJSONFields(t, testCase.topLevel), "top-level publisher required fields")
			for name, typ := range testCase.nestedDefs {
				definition := requireNestedObject(t, schema, "$defs", name)
				assertStringSet(t, objectKeys(requireNestedObject(t, definition, "properties")), publisherJSONFields(t, typ), name+" properties")
			}
		})
	}
}

func publisherJSONFields(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if tag == "" && field.Anonymous {
			fields = append(fields, publisherJSONFields(t, field.Type)...)
			continue
		}
		if tag == "" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			t.Fatalf("empty json tag on %s", field.Name)
		}
		fields = append(fields, name)
	}
	return fields
}

func TestReleasePublisherSchemasValidateRepresentativeDocuments(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	key := releasepublisher.PublicKeyV1{Algorithm: "ed25519", KeyID: "example_root", PublicKey: publicKey}
	config := releasepublisher.ConfigV1{
		SchemaVersion: releasepublisher.ConfigSchemaVersion,
		SourceID:      "example_official", Channel: "stable", SourceType: "registry", SourceClass: "official",
		GeneratedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-10-30T00:00:00Z",
		Root:                 key,
		Signing:              releasepublisher.PublicKeyV1{Algorithm: "ed25519", KeyID: "example_signing", PublicKey: publicKey},
		SigningLedger:        releasepublisher.SigningLedgerConfigV1{LogID: "example_signing_log", PublicKeyV1: releasepublisher.PublicKeyV1{Algorithm: "ed25519", KeyID: "example_ledger", PublicKey: publicKey}},
		AllowedArtifactHosts: []string{"github.com"}, MinReDevPluginVersion: "0.6.22", Distribution: "registry_ref",
		HostRequirements: []releasecontract.ReleaseHostRequirement{},
	}
	reference := releasepublisher.PublisherReleaseRefV1{
		SchemaVersion: releasepublisher.ReleaseRefSchemaVersion,
		ReleaseRef: releasepublisher.PluginReleaseRefV1{
			SourceID: "example_official", Channel: "stable", ReleaseMetadataRef: "sources/example_official/stable/releases/1.json",
			ReleaseMetadataSHA256: strings.Repeat("1", 64), PublisherID: "example.publisher", PluginID: "example.publisher.weather", Version: "1.2.3",
			ExpectedHashes: releasepublisher.PackageHashSetV1{PackageSHA256: "sha256:" + strings.Repeat("2", 64), ManifestSHA256: "sha256:" + strings.Repeat("3", 64), EntriesSHA256: "sha256:" + strings.Repeat("4", 64)},
		},
		Root:          key,
		SigningLedger: releasepublisher.SigningLedgerConfigV1{LogID: "example_signing_log", PublicKeyV1: releasepublisher.PublicKeyV1{Algorithm: "ed25519", KeyID: "example_ledger", PublicKey: publicKey}},
		Files:         []releasepublisher.PublishedFileV1{{Locator: "anchors/root.public.json", AssetName: "root.public.json", SHA256: strings.Repeat("5", 64), Size: 32}},
	}
	for name, document := range map[string]any{
		"release-publisher-config-v1.schema.json": config,
		"publisher-release-ref-v1.schema.json":    reference,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			if err := compilePlatformPackageSchema(t, name).Validate(value); err != nil {
				t.Fatalf("representative publisher document rejected: %v", err)
			}
			value.(map[string]any)["unknown"] = true
			if err := compilePlatformPackageSchema(t, name).Validate(value); err == nil {
				t.Fatal("schema accepted an unknown top-level field")
			}
		})
	}
}
