package capabilitycontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func TestBuildAndVerifyPublishedBundle(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	contract := testContract()
	bundle, err := Build(BuildRequest{
		Contract:                 contract,
		PublisherID:              "example.publisher",
		ArtifactBaseRef:          "capabilities/example.documents/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("a", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		PrivateKey:               privateKey,
		Notices: []Notice{{
			Name:    "example-contract",
			Version: "1.0.0",
			License: "MIT",
		}},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	for _, ref := range []string{
		bundle.Pin.ArtifactRef,
		bundle.Pin.ManifestRef,
		bundle.Pin.SignatureRef,
		bundle.Pin.CompatibilityRef,
		bundle.Pin.GeneratedClientRef,
		bundle.Pin.NoticesRef,
	} {
		if _, ok := bundle.Files[ref]; !ok {
			t.Fatalf("bundle missing %s", ref)
		}
	}

	verified, err := Verify(VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: bundle.Pin,
		TrustedKey: TrustedKey{
			PublisherID:     "example.publisher",
			KeyID:           "example-contract-2026",
			PublicKey:       publicKey,
			PolicyEpoch:     "7",
			RevocationEpoch: "11",
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.Contract.ContractID != contract.ContractID || verified.Contract.CapabilityID != contract.CapabilityID {
		t.Fatalf("verified identity mismatch: %#v", verified.Contract)
	}
	client := string(bundle.Files[bundle.Pin.GeneratedClientRef])
	detailDigest, err := DetailSchemaSHA256(contract.Errors[0].DetailsSchema)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"export class ExampleDocumentsClient",
		"export function isExampleDocumentsBusinessError",
		"capability_id: \"example.capability.documents\"",
		"capability_version: \"1.0.0\"",
		"detail_schema_sha256: \"" + detailDigest + "\"",
		"business_error_code: \"DOCUMENT_NOT_FOUND\"",
		"async list(request: DocumentsListRequest)",
		"async archive(request: DocumentsArchiveRequest)",
		"async watch(request: DocumentsWatchRequest)",
		"PluginOperation<DocumentsArchiveResponse>",
		"export type DocumentsWatchEvent",
		"PluginStream<DocumentsWatchResponse, DocumentsWatchEvent>",
	} {
		if !strings.Contains(client, expected) {
			t.Fatalf("generated client missing %q:\n%s", expected, client)
		}
	}
}

func TestValidateRequiresSignedAsyncConfirmationAndStreamPolicy(t *testing.T) {
	t.Parallel()

	t.Run("operation cancel policy", func(t *testing.T) {
		contract := testContract()
		contract.Methods[1].CancelPolicy = nil
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "cancel_policy") {
			t.Fatalf("Validate() error = %v, want cancel_policy rejection", err)
		}
	})

	t.Run("subscription event contract", func(t *testing.T) {
		contract := testContract()
		contract.Methods[2].EventTypeName = ""
		contract.Methods[2].EventSchema = nil
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "event") {
			t.Fatalf("Validate() error = %v, want event contract rejection", err)
		}
	})

	t.Run("subscription must be cancelable", func(t *testing.T) {
		contract := testContract()
		contract.Methods[2].CancelPolicy.Cancelable = false
		contract.Methods[2].CancelPolicy.AckTimeoutMS = 0
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "subscription") {
			t.Fatalf("Validate() error = %v, want subscription cancelability rejection", err)
		}
	})

	t.Run("confirmation preflight", func(t *testing.T) {
		contract := testContract()
		contract.Methods[1].Confirmation.PreflightMethod = "documents.list"
		contract.Methods[1].Confirmation.PlanHashRequired = true
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "preflight_only") {
			t.Fatalf("Validate() error = %v, want preflight-only rejection", err)
		}
		contract.Methods[0].PreflightOnly = true
		if err := Validate(contract); err != nil {
			t.Fatalf("Validate() rejected signed preflight contract: %v", err)
		}
	})

	t.Run("sync method cannot publish async policy", func(t *testing.T) {
		contract := testContract()
		contract.Methods[0].CancelPolicy = &CancelPolicy{
			Cancelable:        true,
			DisableBehavior:   "cancel",
			UninstallBehavior: "cancel_then_block_delete",
			AckTimeoutMS:      1000,
		}
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "sync") {
			t.Fatalf("Validate() error = %v, want sync policy rejection", err)
		}
	})
}

func TestGenerateTypeScriptPreservesCancelabilityAndPrimitiveLiterals(t *testing.T) {
	t.Parallel()
	contract := testContract()
	contract.Methods[1].CancelPolicy.Cancelable = false
	contract.Methods[1].CancelPolicy.AckTimeoutMS = 0
	contract.Methods[0].RequestSchema = objectSchema(map[string]any{
		"workspace_id": map[string]any{"type": "string", "minLength": 1},
		"priority":     map[string]any{"type": "integer", "enum": []any{1, 2, 3}},
		"ratio":        map[string]any{"type": "number", "const": 0.5},
		"dry_run":      map[string]any{"type": "boolean", "const": true},
	}, []string{"workspace_id", "priority", "ratio", "dry_run"})

	clientBytes, err := GenerateTypeScript(contract)
	if err != nil {
		t.Fatalf("GenerateTypeScript() error = %v", err)
	}
	client := string(clientBytes)
	for _, expected := range []string{
		"priority: 1 | 2 | 3;",
		"ratio: 0.5;",
		"dry_run: true;",
		"PluginOperation<DocumentsArchiveResponse, false>",
		"callCapabilityOperation<DocumentsArchiveRequest, DocumentsArchiveResponse, false>",
		"      false,",
	} {
		if !strings.Contains(client, expected) {
			t.Fatalf("generated client missing %q:\n%s", expected, client)
		}
	}
}

func TestVerifyRejectsEveryPinnedArtifactMutation(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract:                 testContract(),
		PublisherID:              "example.publisher",
		ArtifactBaseRef:          "capabilities/example.documents/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("b", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	refs := []string{
		bundle.Pin.ArtifactRef,
		bundle.Pin.ManifestRef,
		bundle.Pin.SignatureRef,
		bundle.Pin.CompatibilityRef,
		bundle.Pin.GeneratedClientRef,
		bundle.Pin.NoticesRef,
	}
	for _, ref := range refs {
		ref := ref
		t.Run(ref, func(t *testing.T) {
			t.Parallel()
			tampered := cloneBundle(bundle)
			tampered.Files[ref] = append(append([]byte(nil), tampered.Files[ref]...), byte('\n'))
			if _, err := Verify(VerifyRequest{
				Bundle:      tampered,
				ExpectedPin: bundle.Pin,
				TrustedKey: TrustedKey{
					PublisherID:     "example.publisher",
					KeyID:           "example-contract-2026",
					PublicKey:       publicKey,
					PolicyEpoch:     "7",
					RevocationEpoch: "11",
				},
				CurrentReDevPluginVersion: "0.3.0",
			}); err == nil {
				t.Fatalf("Verify() accepted tampered %s", ref)
			}
		})
	}
}

func TestVerifyRejectsResignedStaleGeneratedClient(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract:                 testContract(),
		PublisherID:              "example.publisher",
		ArtifactBaseRef:          "capabilities/example.documents/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("e", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	tampered := cloneBundle(bundle)
	staleClient := []byte("export class StaleGeneratedClient {}\n")
	tampered.Files[tampered.Pin.GeneratedClientRef] = staleClient
	var manifest Manifest
	if err := strictJSON(tampered.Files[tampered.Pin.ManifestRef], &manifest); err != nil {
		t.Fatal(err)
	}
	for index := range manifest.Entries {
		if manifest.Entries[index].Role == "generated_client" {
			manifest.Entries[index] = manifestEntry("generated_client", tampered.Pin.GeneratedClientRef, "text/typescript", staleClient)
		}
	}
	manifestBytes, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Files[tampered.Pin.ManifestRef] = manifestBytes
	tampered.Pin.ManifestSHA256 = sha256Hex(manifestBytes)
	tampered.Pin.GeneratedClientSHA256 = sha256Hex(staleClient)
	signatureBytes, err := canonicalJSON(SignatureEnvelope{
		SchemaVersion:   signatureSchemaVersion,
		Algorithm:       signatureAlgorithm,
		KeyID:           tampered.Pin.SignatureKeyID,
		ManifestSHA256:  tampered.Pin.ManifestSHA256,
		SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered.Files[tampered.Pin.SignatureRef] = signatureBytes
	tampered.Pin.SignatureSHA256 = sha256Hex(signatureBytes)

	if _, err := Verify(VerifyRequest{
		Bundle:      tampered,
		ExpectedPin: tampered.Pin,
		TrustedKey: TrustedKey{
			PublisherID:     tampered.Pin.PublisherID,
			KeyID:           tampered.Pin.SignatureKeyID,
			PublicKey:       publicKey,
			PolicyEpoch:     tampered.Pin.SignaturePolicyEpoch,
			RevocationEpoch: tampered.Pin.SignatureRevocationEpoch,
		},
		CurrentReDevPluginVersion: "0.3.0",
	}); err == nil {
		t.Fatal("Verify() accepted a fully re-signed generated client that diverges from the contract")
	}
}

func TestVerifyRejectsTrustAndCompatibilityMismatches(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract:                 testContract(),
		PublisherID:              "example.publisher",
		ArtifactBaseRef:          "capabilities/example.documents/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("d", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	validKey := TrustedKey{
		PublisherID:     "example.publisher",
		KeyID:           "example-contract-2026",
		PublicKey:       publicKey,
		PolicyEpoch:     "7",
		RevocationEpoch: "11",
	}

	t.Run("wrong signing key", func(t *testing.T) {
		key := validKey
		key.PublicKey = otherPublicKey
		if _, err := Verify(VerifyRequest{Bundle: bundle, ExpectedPin: bundle.Pin, TrustedKey: key, CurrentReDevPluginVersion: "0.3.0"}); !errors.Is(err, ErrSignature) {
			t.Fatalf("Verify() error = %v, want ErrSignature", err)
		}
	})

	t.Run("publisher mismatch", func(t *testing.T) {
		key := validKey
		key.PublisherID = "other.publisher"
		if _, err := Verify(VerifyRequest{Bundle: bundle, ExpectedPin: bundle.Pin, TrustedKey: key, CurrentReDevPluginVersion: "0.3.0"}); !errors.Is(err, ErrSignature) {
			t.Fatalf("Verify() error = %v, want ErrSignature", err)
		}
	})

	t.Run("stale compatibility", func(t *testing.T) {
		if _, err := Verify(VerifyRequest{Bundle: bundle, ExpectedPin: bundle.Pin, TrustedKey: validKey, CurrentReDevPluginVersion: "0.2.2"}); !errors.Is(err, ErrCompatibility) {
			t.Fatalf("Verify() error = %v, want ErrCompatibility", err)
		}
	})
}

func TestRestrictedSchemaConformanceFixture(t *testing.T) {
	t.Parallel()
	var fixture struct {
		SchemaVersion string `json:"schema_version"`
		Cases         []struct {
			Name   string         `json:"name"`
			Schema map[string]any `json:"schema"`
			Value  any            `json:"value"`
			Valid  bool           `json:"valid"`
		} `json:"cases"`
	}
	readJSONFixture(t, filepath.Join("..", "..", "testdata", "host-capability", "restricted-schema-conformance-v1.json"), &fixture)
	if fixture.SchemaVersion != "redevplugin.restricted_schema_conformance.v1" || len(fixture.Cases) == 0 {
		t.Fatalf("invalid restricted-schema conformance fixture: %#v", fixture)
	}
	for _, testCase := range fixture.Cases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			err := ValidateValue(testCase.Schema, testCase.Value)
			if testCase.Valid && err != nil {
				t.Fatalf("ValidateValue() error = %v", err)
			}
			if !testCase.Valid && err == nil {
				t.Fatal("ValidateValue() accepted invalid fixture value")
			}
		})
	}
}

func TestPublishedSampleArtifactVerifies(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "testdata", "host-capability", "sample-documents-v1")
	var pin Pin
	readJSONFixture(t, filepath.Join(root, "host-capability.pin.json"), &pin)
	var publicDocument struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	readJSONFixture(t, filepath.Join(root, "example-documents.public.json"), &publicDocument)
	publicKey, err := base64.StdEncoding.DecodeString(publicDocument.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{Pin: pin, Files: map[string][]byte{}}
	for _, ref := range []string{pin.ArtifactRef, pin.ManifestRef, pin.SignatureRef, pin.CompatibilityRef, pin.GeneratedClientRef, pin.NoticesRef} {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ref)))
		if err != nil {
			t.Fatal(err)
		}
		bundle.Files[ref] = content
	}
	verified, err := Verify(VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: pin,
		TrustedKey: TrustedKey{
			PublisherID:     pin.PublisherID,
			KeyID:           publicDocument.KeyID,
			PublicKey:       publicKey,
			PolicyEpoch:     pin.SignaturePolicyEpoch,
			RevocationEpoch: pin.SignatureRevocationEpoch,
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatalf("Verify(sample) error = %v", err)
	}
	if verified.Contract.ContractID != "example.documents.v1" || verified.Contract.CapabilityID != "example.capability.documents" {
		t.Fatalf("sample identity mismatch: %#v", verified.Contract)
	}
}

func TestVerifyRejectsArtifactsAboveResourceBudgets(t *testing.T) {
	bundle, publicKey := signedBundleForTest(t)
	oversized := bytes.Repeat([]byte{'x'}, int(MaxArtifactFileBytes)+1)
	bundle.Files[bundle.Pin.ArtifactRef] = oversized
	bundle.Pin.ArtifactSHA256 = sha256Hex(oversized)
	_, err := Verify(VerifyRequest{
		Bundle: bundle, ExpectedPin: bundle.Pin,
		TrustedKey: TrustedKey{
			PublisherID: bundle.Pin.PublisherID, KeyID: bundle.Pin.SignatureKeyID, PublicKey: publicKey,
			PolicyEpoch: bundle.Pin.SignaturePolicyEpoch, RevocationEpoch: bundle.Pin.SignatureRevocationEpoch,
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if !errors.Is(err, ErrInvalidBundle) || !strings.Contains(err.Error(), "per-file byte budget") {
		t.Fatalf("Verify() error = %v, want resource budget rejection", err)
	}
}

func TestValidateValueRejectsSchemaAboveComplexityBudgets(t *testing.T) {
	schema := map[string]any{"type": "string"}
	for index := 0; index < MaxSchemaDepth; index++ {
		schema = map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties":           map[string]any{"child": schema},
		}
	}
	if err := ValidateValue(schema, map[string]any{}); !errors.Is(err, ErrInvalidContract) || !strings.Contains(err.Error(), "maximum schema depth") {
		t.Fatalf("ValidateValue() error = %v, want schema depth rejection", err)
	}
}

func TestRegistryRequiresExactVerifiedPin(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract:                 testContract(),
		PublisherID:              "example.publisher",
		ArtifactBaseRef:          "capabilities/example.documents/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("c", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: bundle.Pin,
		TrustedKey: TrustedKey{
			PublisherID:     "example.publisher",
			KeyID:           "example-contract-2026",
			PublicKey:       publicKey,
			PolicyEpoch:     "7",
			RevocationEpoch: "11",
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.Add(verified); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if _, err := registry.Require(bundle.Pin); err != nil {
		t.Fatalf("Require() error = %v", err)
	}
	tamperedPin := bundle.Pin
	tamperedPin.GeneratedClientSHA256 = strings.Repeat("0", 64)
	if _, err := registry.Require(tamperedPin); err == nil {
		t.Fatal("Require() accepted a mismatched generated client pin")
	}
}

func TestRegistryDeepClonesVerifiedContracts(t *testing.T) {
	t.Parallel()
	verified := buildVerifiedTestContract(t, testContract(), "deep-clone")
	registry := NewRegistry()
	if err := registry.Add(verified); err != nil {
		t.Fatal(err)
	}

	verified.Contract.Methods[0].RequestSchema["properties"].(map[string]any)["workspace_id"].(map[string]any)["minLength"] = 99
	verified.Contract.Methods[1].Confirmation.RequestHashFields[0] = "mutated"
	verified.Contract.Errors[0].DetailsSchema["properties"].(map[string]any)["document_id"].(map[string]any)["minLength"] = 99

	first, err := registry.Require(verified.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Contract.Methods[0].RequestSchema["properties"].(map[string]any)["workspace_id"].(map[string]any)["minLength"]; got != float64(1) {
		t.Fatalf("registry retained caller mutation after Add(): minLength = %#v", got)
	}
	if got := first.Contract.Methods[1].Confirmation.RequestHashFields[0]; got != "document_id" {
		t.Fatalf("registry retained confirmation mutation after Add(): %q", got)
	}
	if got := first.Contract.Errors[0].DetailsSchema["properties"].(map[string]any)["document_id"].(map[string]any)["minLength"]; got != float64(1) {
		t.Fatalf("registry retained business error mutation after Add(): minLength = %#v", got)
	}

	first.Contract.Methods[0].ResponseSchema["properties"].(map[string]any)["documents"].(map[string]any)["items"].(map[string]any)["required"].([]any)[0] = "mutated"
	second, err := registry.Require(verified.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Contract.Methods[0].ResponseSchema["properties"].(map[string]any)["documents"].(map[string]any)["items"].(map[string]any)["required"].([]any)[0]; got != "document_id" {
		t.Fatalf("registry return value mutated stored contract: %q", got)
	}
}

func TestRegistryRejectsForgedOrMutatedVerifiedContracts(t *testing.T) {
	t.Parallel()
	verified := buildVerifiedTestContract(t, testContract(), "verification-seal")
	forged := verified
	forged.verificationSeal = ""
	if err := NewRegistry().Add(forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("Add(forged) error = %v, want ErrSignature", err)
	}

	mutated := verified
	mutated.Contract.Methods[0].Effect = "admin"
	if err := NewRegistry().Add(mutated); !errors.Is(err, ErrSignature) {
		t.Fatalf("Add(mutated) error = %v, want ErrSignature", err)
	}
}

func buildVerifiedTestContract(t *testing.T, contract Contract, suffix string) VerifiedContract {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract:                 contract,
		PublisherID:              contract.PublisherID,
		ArtifactBaseRef:          "capabilities/tests/" + suffix,
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("f", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "test-contract-key",
		SignaturePolicyEpoch:     "1",
		SignatureRevocationEpoch: "1",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: bundle.Pin,
		TrustedKey: TrustedKey{
			PublisherID: contract.PublisherID, KeyID: "test-contract-key", PublicKey: publicKey,
			PolicyEpoch: "1", RevocationEpoch: "1",
		},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestValidateArtifactRefRejectsUnsafeSources(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{
		"https://registry.example/capability.json",
		"http://127.0.0.1/capability.json",
		"file:///tmp/capability.json",
		"../redeven/contract.json",
		"capabilities/%2e%2e/contract.json",
		"/absolute/contract.json",
		"capabilities\\contract.json",
	} {
		if err := ValidateArtifactRef(ref); err == nil {
			t.Fatalf("ValidateArtifactRef(%q) succeeded", ref)
		}
	}
}

func TestSchemaSupportsClosedEmptyObjectsAndBoundedOneOf(t *testing.T) {
	t.Parallel()
	emptyObject := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
	}
	if err := ValidateValue(emptyObject, map[string]any{}); err != nil {
		t.Fatalf("ValidateValue() rejected a closed empty object: %v", err)
	}
	if err := ValidateValue(emptyObject, map[string]any{"unexpected": true}); err == nil {
		t.Fatal("ValidateValue() accepted an undeclared object property")
	}

	union := map[string]any{
		"oneOf": []any{
			map[string]any{"type": "string"},
			map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"id": map[string]any{"type": "string"},
				},
				"required": []any{"id"},
			},
		},
	}
	for _, value := range []any{"message", map[string]any{"id": "risk_1"}} {
		if err := ValidateValue(union, value); err != nil {
			t.Fatalf("ValidateValue() rejected %#v: %v", value, err)
		}
	}
	if err := ValidateValue(union, 42); err == nil {
		t.Fatal("ValidateValue() accepted a value outside oneOf")
	}
	typeScript, err := schemaTypeScript(union, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(typeScript, "string | {") {
		t.Fatalf("schemaTypeScript() union = %q", typeScript)
	}
}

func TestMachineSchemaMatchesRuntimeRestrictedSchema(t *testing.T) {
	t.Parallel()
	schemaPath := filepath.Join("..", "..", "spec", "plugin", "host-capability-contract-v1.schema.json")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:redevplugin:host-capability-contract", bytes.NewReader(schemaBytes)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:redevplugin:host-capability-contract")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(testContract())
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(document); err != nil {
		t.Fatalf("machine schema rejected runtime-valid contract: %v", err)
	}

	invalid := testContract()
	invalid.Methods[0].TargetSchema = map[string]any{"type": "object"}
	raw, err = json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(document); err == nil {
		t.Fatal("machine schema accepted an open object schema")
	}
}

func TestValidateSchemaRejectsMalformedRestrictedKeywords(t *testing.T) {
	t.Parallel()
	cases := []map[string]any{
		{"type": "string", "minLength": 2, "maxLength": 1},
		{"type": "string", "format": "uri"},
		{"type": "integer", "multipleOf": 0},
		{"type": "array", "items": map[string]any{"type": "string"}, "uniqueItems": "yes"},
		{"oneOf": []any{map[string]any{"type": "string"}, map[string]any{"type": "string"}}},
		{"type": "object", "additionalProperties": false, "properties": map[string]any{"__proto__": map[string]any{"type": "string"}}},
	}
	for _, schema := range cases {
		if err := validateSchema(schema, "fixture"); err == nil {
			t.Fatalf("validateSchema() accepted malformed schema: %#v", schema)
		}
	}
}

func TestContractValidationRejectsNonCanonicalSemverAndStringSets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Contract)
	}{
		{name: "contract version whitespace", mutate: func(contract *Contract) { contract.ContractVersion = " 1.0.0" }},
		{name: "capability version whitespace", mutate: func(contract *Contract) { contract.CapabilityVersion = "1.0.0 " }},
		{name: "short contract version", mutate: func(contract *Contract) { contract.ContractVersion = "1.0" }},
		{name: "short capability version", mutate: func(contract *Contract) { contract.CapabilityVersion = "1" }},
		{name: "numeric prerelease leading zero", mutate: func(contract *Contract) { contract.ContractVersion = "1.0.0-01" }},
		{name: "reserved client name", mutate: func(contract *Contract) { contract.ClientName = "class" }},
		{name: "reserved client method", mutate: func(contract *Contract) { contract.Methods[0].ClientMethod = "constructor" }},
		{name: "prototype-sensitive property", mutate: func(contract *Contract) {
			contract.Methods[0].RequestSchema["properties"].(map[string]any)["__proto__"] = map[string]any{"type": "string"}
		}},
		{name: "duplicate required permission", mutate: func(contract *Contract) {
			contract.Methods[0].RequiredPermissions = []string{"documents.read", "documents.read"}
		}},
		{name: "permission whitespace", mutate: func(contract *Contract) {
			contract.Methods[0].RequiredPermissions = []string{" documents.read"}
		}},
		{name: "duplicate target field", mutate: func(contract *Contract) {
			contract.Methods[0].TargetFields = []string{"workspace_id", "workspace_id"}
		}},
		{name: "duplicate confirmation hash field", mutate: func(contract *Contract) {
			contract.Methods[1].Confirmation.RequestHashFields = []string{"document_id", "document_id"}
		}},
	}

	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "spec", "plugin", "host-capability-contract-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:redevplugin:host-capability-contract:canonical", bytes.NewReader(schemaBytes)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:redevplugin:host-capability-contract:canonical")
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			contract := testContract()
			testCase.mutate(&contract)
			if err := Validate(contract); err == nil {
				t.Fatal("Validate() accepted a non-canonical contract")
			}
			raw, err := json.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			var document any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if err := compiled.Validate(document); err == nil {
				t.Fatal("machine schema accepted a non-canonical contract")
			}
		})
	}
}

func TestContractValidationRejectsDuplicateGeneratedTypeNames(t *testing.T) {
	t.Parallel()
	contract := testContract()
	contract.Methods[1].RequestTypeName = contract.Methods[0].ResponseTypeName
	if err := Validate(contract); err == nil {
		t.Fatal("Validate() accepted duplicate generated TypeScript names")
	}
}

func TestContractValidationRejectsGeneratedTypeNamesReservedByTheSDK(t *testing.T) {
	t.Parallel()
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "spec", "plugin", "host-capability-contract-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("urn:redevplugin:host-capability-contract:sdk-names", bytes.NewReader(schemaBytes)); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("urn:redevplugin:host-capability-contract:sdk-names")
	if err != nil {
		t.Fatal(err)
	}
	reserved := []string{
		"PluginBridgeClient",
		"PluginBridgeError",
		"PluginOperation",
		"PluginStream",
		"callCapabilityOperation",
		"callCapabilityStream",
		"callCapabilitySync",
		"decodePluginStreamText",
		"isCapabilityBusinessError",
	}
	for _, name := range reserved {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			contract := testContract()
			contract.Methods[0].RequestTypeName = name
			if err := Validate(contract); err == nil {
				t.Fatalf("Validate() accepted SDK-reserved generated type name %q", name)
			}
			raw, err := json.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			var document any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if err := compiled.Validate(document); err == nil {
				t.Fatalf("machine schema accepted SDK-reserved generated type name %q", name)
			}
		})
	}
}

func TestGenerateTypeScriptFormatsMultipleBusinessErrorsAsAUnion(t *testing.T) {
	t.Parallel()
	contract := testContract()
	contract.Errors = append(contract.Errors, BusinessError{Code: "DOCUMENT_LOCKED", Message: "Document is locked"})
	client, err := GenerateTypeScript(contract)
	if err != nil {
		t.Fatal(err)
	}
	text := string(client)
	if strings.Count(text, "\n  | {\n") != 2 || strings.Contains(text, "  };\n  | {") {
		t.Fatalf("generated business error union is invalid:\n%s", text)
	}
}

func TestRestrictedSchemaRejectsDuplicateAndEmptyStringSets(t *testing.T) {
	t.Parallel()
	for _, required := range [][]any{{"id", "id"}, {""}} {
		schema := map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties":           map[string]any{"id": map[string]any{"type": "string"}},
			"required":             required,
		}
		if err := validateSchema(schema, "fixture"); err == nil {
			t.Fatalf("validateSchema() accepted required=%#v", required)
		}
	}
}

func TestPinValidationRejectsDuplicateRefsAndNonCanonicalDigests(t *testing.T) {
	t.Parallel()
	pin := testPin()
	pin.GeneratedClientRef = pin.ArtifactRef
	if err := validatePin(pin); err == nil {
		t.Fatal("validatePin() accepted duplicate artifact refs")
	}
	pin = testPin()
	pin.ArtifactSHA256 = strings.ToUpper(pin.ArtifactSHA256)
	if err := validatePin(pin); err == nil {
		t.Fatal("validatePin() accepted a non-canonical digest")
	}
}

func TestArtifactRefsUseTheSameRestrictedAlphabetAsPublishedSchemas(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{
		"capabilities/example@publisher/contract.json",
		"capabilities/example+preview/contract.json",
		"capabilities/example!/contract.json",
	} {
		if err := ValidateArtifactRef(ref); err == nil {
			t.Fatalf("ValidateArtifactRef(%q) accepted a ref rejected by the published schemas", ref)
		}
	}
	if err := ValidateArtifactRef("capabilities/example.publisher/v1.0.0/contract.json"); err != nil {
		t.Fatalf("ValidateArtifactRef() rejected canonical ref: %v", err)
	}
}

func TestVerifyRejectsDevelopmentVersionAsCompatibilityAuthority(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract:                 testContract(),
		PublisherID:              "example.publisher",
		ArtifactBaseRef:          "capabilities/example.documents/v1.0.0",
		GeneratedAt:              time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC),
		SourceCommit:             strings.Repeat("a", 40),
		MinReDevPluginVersion:    "0.3.0",
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		PrivateKey:               privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(VerifyRequest{
		Bundle:      bundle,
		ExpectedPin: bundle.Pin,
		TrustedKey: TrustedKey{
			PublisherID:     bundle.Pin.PublisherID,
			KeyID:           bundle.Pin.SignatureKeyID,
			PublicKey:       publicKey,
			PolicyEpoch:     bundle.Pin.SignaturePolicyEpoch,
			RevocationEpoch: bundle.Pin.SignatureRevocationEpoch,
		},
		CurrentReDevPluginVersion: "0.0.0-dev",
	})
	if !errors.Is(err, ErrCompatibility) {
		t.Fatalf("Verify() error = %v, want ErrCompatibility", err)
	}
}

func testContract() Contract {
	return Contract{
		SchemaVersion:     SchemaVersion,
		ContractID:        "example.documents.v1",
		ContractVersion:   "1.0.0",
		PublisherID:       "example.publisher",
		CapabilityID:      "example.capability.documents",
		CapabilityVersion: "1.0.0",
		ClientName:        "ExampleDocumentsClient",
		Errors: []BusinessError{{
			Code:    "DOCUMENT_NOT_FOUND",
			Message: "Document not found",
			DetailsSchema: objectSchema(map[string]any{
				"document_id": map[string]any{"type": "string", "minLength": 1},
			}, []string{"document_id"}),
		}},
		Methods: []Method{
			{
				Name:                "documents.list",
				ClientMethod:        "list",
				Effect:              "read",
				Execution:           "sync",
				RequiredPermissions: []string{"documents.read"},
				TargetFields:        []string{"workspace_id"},
				TargetSchema: objectSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string", "minLength": 1},
				}, []string{"workspace_id"}),
				RequestTypeName:  "DocumentsListRequest",
				ResponseTypeName: "DocumentsListResponse",
				RequestSchema: objectSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string", "minLength": 1},
				}, []string{"workspace_id"}),
				ResponseSchema: objectSchema(map[string]any{
					"documents": map[string]any{
						"type": "array",
						"items": objectSchema(map[string]any{
							"document_id": map[string]any{"type": "string"},
							"title":       map[string]any{"type": "string"},
						}, []string{"document_id", "title"}),
					},
				}, []string{"documents"}),
			},
			{
				Name:                "documents.archive",
				ClientMethod:        "archive",
				Effect:              "write",
				Execution:           "operation",
				RequiredPermissions: []string{"documents.manage"},
				TargetFields:        []string{"document_id"},
				TargetSchema: objectSchema(map[string]any{
					"document_id": map[string]any{"type": "string", "minLength": 1},
				}, []string{"document_id"}),
				RequestTypeName:  "DocumentsArchiveRequest",
				ResponseTypeName: "DocumentsArchiveResponse",
				RequestSchema: objectSchema(map[string]any{
					"document_id": map[string]any{"type": "string", "minLength": 1},
				}, []string{"document_id"}),
				ResponseSchema: objectSchema(map[string]any{
					"accepted": map[string]any{"type": "boolean"},
				}, []string{"accepted"}),
				Confirmation: &Confirmation{
					Mode:              "required",
					RequestHashFields: []string{"document_id"},
				},
				CancelPolicy: &CancelPolicy{
					Cancelable:        true,
					DisableBehavior:   "cancel",
					UninstallBehavior: "cancel_then_block_delete",
					AckTimeoutMS:      1000,
				},
				Quota: Quota{MaxConcurrent: 2, MaxDurationMS: 30000},
			},
			{
				Name:                "documents.watch",
				ClientMethod:        "watch",
				Effect:              "read",
				Execution:           "subscription",
				RequiredPermissions: []string{"documents.read"},
				TargetFields:        []string{"workspace_id"},
				TargetSchema: objectSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string", "minLength": 1},
				}, []string{"workspace_id"}),
				RequestTypeName:  "DocumentsWatchRequest",
				ResponseTypeName: "DocumentsWatchResponse",
				RequestSchema: objectSchema(map[string]any{
					"workspace_id": map[string]any{"type": "string", "minLength": 1},
				}, []string{"workspace_id"}),
				ResponseSchema: objectSchema(map[string]any{
					"watching": map[string]any{"type": "boolean"},
				}, []string{"watching"}),
				EventTypeName: "DocumentsWatchEvent",
				EventSchema: objectSchema(map[string]any{
					"document_id": map[string]any{"type": "string", "minLength": 1},
					"change":      map[string]any{"type": "string", "enum": []any{"created", "updated", "deleted"}},
				}, []string{"document_id", "change"}),
				CancelPolicy: &CancelPolicy{
					Cancelable:        true,
					DisableBehavior:   "cancel",
					UninstallBehavior: "cancel_then_block_delete",
					AckTimeoutMS:      1000,
				},
				Quota: Quota{MaxConcurrent: 4, MaxStreamBytes: 1048576},
			},
		},
	}
}

func objectSchema(properties map[string]any, required []string) map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
		"required":             required,
	}
}

func testPin() Pin {
	return Pin{
		PublisherID:              "example.publisher",
		ContractID:               "example.documents.v1",
		ContractVersion:          "1.0.0",
		ArtifactRef:              "capabilities/example/contract.json",
		ArtifactSHA256:           strings.Repeat("ab", 32),
		ManifestRef:              "capabilities/example/manifest.json",
		ManifestSHA256:           strings.Repeat("2", 64),
		SignatureRef:             "capabilities/example/manifest.sig",
		SignatureSHA256:          strings.Repeat("3", 64),
		SignatureKeyID:           "example-contract-2026",
		SignaturePolicyEpoch:     "7",
		SignatureRevocationEpoch: "11",
		CompatibilityRef:         "capabilities/example/compatibility.json",
		CompatibilitySHA256:      strings.Repeat("4", 64),
		GeneratedClientRef:       "capabilities/example/client.ts",
		GeneratedClientSHA256:    strings.Repeat("5", 64),
		NoticesRef:               "capabilities/example/notices.json",
		NoticesSHA256:            strings.Repeat("6", 64),
	}
}

func cloneBundle(bundle Bundle) Bundle {
	cloned := Bundle{Pin: bundle.Pin, Files: make(map[string][]byte, len(bundle.Files))}
	for ref, content := range bundle.Files {
		cloned.Files[ref] = append([]byte(nil), content...)
	}
	return cloned
}

func signedBundleForTest(t *testing.T) (Bundle, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Build(BuildRequest{
		Contract: testContract(), PublisherID: "example.publisher", ArtifactBaseRef: "capabilities/example/documents/v1.0.0",
		GeneratedAt: time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC), SourceCommit: strings.Repeat("a", 40),
		MinReDevPluginVersion: "0.3.0", SignatureKeyID: "example-contract-2026",
		SignaturePolicyEpoch: "7", SignatureRevocationEpoch: "11", PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle, publicKey
}

func readJSONFixture(t *testing.T, filename string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}
