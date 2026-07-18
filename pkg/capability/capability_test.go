package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/pkg/capabilitycontract"
)

func TestNewBusinessErrorOwnsCanonicalAdapterDetails(t *testing.T) {
	nested := map[string]any{"items": []any{map[string]any{"value": "original"}}}
	businessError, err := NewBusinessError("FAILED", "failed", nested)
	if err != nil {
		t.Fatal(err)
	}
	nested["items"].([]any)[0].(map[string]any)["value"] = "changed"
	if got := businessError.Details["items"].([]any)[0].(map[string]any)["value"]; got != "original" {
		t.Fatalf("NewBusinessError() retained nested adapter details: %#v", got)
	}
}

func TestNewBusinessErrorRejectsNonCanonicalAdapterDetails(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, details := range []map[string]any{
		{"cycle": cycle},
		{"integer": 1},
	} {
		if _, err := NewBusinessError("FAILED", "failed", details); err == nil {
			t.Fatalf("NewBusinessError() accepted non-canonical details %#v", details)
		}
	}
}

func TestOwnExecutionBindingRejectsNonCanonicalTargetFields(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, value := range []any{
		1,
		float64(1 << 53),
		json.Number("9007199254740992"),
		[]string{"value"},
		cycle,
	} {
		binding := testExecutionBinding(map[string]any{"invalid": value})
		if _, err := OwnExecutionBinding(binding); err == nil {
			t.Fatalf("OwnExecutionBinding() accepted non-canonical target value %T", value)
		}
	}
}

func TestOwnExecutionBindingIsolatesConcurrentAdapterMutation(t *testing.T) {
	input := map[string]any{"nested": []any{map[string]any{"value": "original"}}}
	owned, err := OwnExecutionBinding(testExecutionBinding(input))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			input["nested"].([]any)[0].(map[string]any)["value"] = "mutated"
		}
	}()
	for range 1000 {
		if got := owned.Target.Fields["nested"].([]any)[0].(map[string]any)["value"]; got != "original" {
			t.Fatalf("owned binding observed adapter mutation: %#v", got)
		}
	}
	<-done
}

func TestOwnExecutionBindingReducesSnapshotAllocations(t *testing.T) {
	binding := largeExecutionBindingFixture()
	var owned ExecutionBinding
	var roundTripped ExecutionBinding
	ownedAllocs := testing.AllocsPerRun(50, func() {
		var err error
		owned, err = OwnExecutionBinding(binding)
		if err != nil {
			panic(err)
		}
	})
	roundTripAllocs := testing.AllocsPerRun(50, func() {
		raw, err := json.Marshal(binding)
		if err != nil {
			panic(err)
		}
		if err := json.Unmarshal(raw, &roundTripped); err != nil {
			panic(err)
		}
	})
	if owned.Target.Fields == nil || roundTripped.Target.Fields == nil {
		t.Fatal("allocation fixtures were optimized away")
	}
	if ownedAllocs > roundTripAllocs*0.20 {
		t.Fatalf("owned snapshot allocations = %.2f, JSON round trip = %.2f; want at least 80%% reduction", ownedAllocs, roundTripAllocs)
	}
}

func BenchmarkExecutionBindingSnapshot(b *testing.B) {
	binding := largeExecutionBindingFixture()
	b.Run("owned-canonical-clone", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := OwnExecutionBinding(binding); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("json-round-trip", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			raw, err := json.Marshal(binding)
			if err != nil {
				b.Fatal(err)
			}
			var cloned ExecutionBinding
			if err := json.Unmarshal(raw, &cloned); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func testExecutionBinding(fields map[string]any) ExecutionBinding {
	return ExecutionBinding{
		Permissions: PermissionEvidence{Required: []string{}, Granted: []string{}},
		Target:      TargetDescriptor{Kind: "test", Fields: fields},
	}
}

func largeExecutionBindingFixture() ExecutionBinding {
	fields := make(map[string]any, 1024)
	for index := range 1024 {
		fields[fmt.Sprintf("field_%04d", index)] = "snapshot-value"
	}
	return testExecutionBinding(fields)
}

func TestRegistryOwnsExactContractPins(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	contracts := []capabilitycontract.VerifiedContract{
		testVerifiedContract(t, "1.0.0", "1.0.0"),
		testVerifiedContract(t, "1.0.0", "1.1.0"),
	}
	for _, contract := range contracts {
		adapter := &testAdapter{}
		if err := registry.Register(Registration{Contract: contract, TargetProjector: adapter, Adapter: adapter}); err != nil {
			t.Fatalf("Register(%s) error = %v", contract.Pin.ContractVersion, err)
		}
	}
	for _, contract := range contracts {
		registration, err := registry.Resolve(contract.Pin)
		if err != nil {
			t.Fatal(err)
		}
		if registration.Contract.Pin != contract.Pin || registration.Adapter == nil || registration.TargetProjector == nil {
			t.Fatalf("Resolve() returned an incomplete exact registration: %#v", registration)
		}
	}
}

func TestRegistryDeepClonesContractBoundaries(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	contract := testVerifiedContract(t, "1.0.0", "1.0.0")
	adapter := &testAdapter{}
	if err := registry.Register(Registration{Contract: contract, TargetProjector: adapter, Adapter: adapter}); err != nil {
		t.Fatal(err)
	}
	contract.Contract.Methods[0].RequestSchema["properties"].(map[string]any)["document_id"].(map[string]any)["minLength"] = 99

	first, err := registry.RequireContract(contract.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Contract.Methods[0].RequestSchema["properties"].(map[string]any)["document_id"].(map[string]any)["minLength"]; got != float64(1) {
		t.Fatalf("registry retained caller mutation: %#v", got)
	}
	first.Contract.Methods[0].ResponseSchema["properties"].(map[string]any)["accepted"].(map[string]any)["type"] = "string"
	second, err := registry.RequireContract(first.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Contract.Methods[0].ResponseSchema["properties"].(map[string]any)["accepted"].(map[string]any)["type"]; got != "boolean" {
		t.Fatalf("registry return value mutated stored contract: %#v", got)
	}
}

func TestRegistryRequiresExplicitTargetProjector(t *testing.T) {
	t.Parallel()
	if err := NewRegistry().Register(Registration{Contract: testVerifiedContract(t, "1.0.0", "1.0.0"), Adapter: &testAdapter{}}); !strings.Contains(err.Error(), "target projector") {
		t.Fatalf("Register() error = %v, want target projector requirement", err)
	}
}

func TestExecutionFailureCodesAreClosed(t *testing.T) {
	for _, code := range []ExecutionFailureCode{
		ExecutionFailureAdapterFailed,
		ExecutionFailureContractInvalid,
		ExecutionFailurePlatformFailed,
		ExecutionFailureQuotaExceeded,
		ExecutionFailureRuntimeFailed,
	} {
		if !code.Valid() {
			t.Fatalf("failure code %q is not valid", code)
		}
	}
	for _, code := range []ExecutionFailureCode{"", "adapter_error", "internal"} {
		if code.Valid() {
			t.Fatalf("unknown failure code %q is valid", code)
		}
	}
}

type testAdapter struct{}

func (*testAdapter) ProjectTarget(_ context.Context, req TargetResolutionRequest) (TargetDescriptor, error) {
	return TargetDescriptor{Kind: "document", Fields: req.TargetInput}, nil
}

func (*testAdapter) Invoke(_ context.Context, _ Invocation) (Result, error) {
	return Result{Data: map[string]any{"accepted": true}}, nil
}

func testVerifiedContract(t *testing.T, capabilityVersion, contractVersion string) capabilitycontract.VerifiedContract {
	t.Helper()
	contract := capabilitycontract.Contract{
		SchemaVersion:     capabilitycontract.SchemaVersion,
		ContractID:        "example.documents.v1",
		ContractVersion:   contractVersion,
		PublisherID:       "example.publisher",
		CapabilityID:      "example.capability.documents",
		CapabilityVersion: capabilityVersion,
		ClientName:        "ExampleDocumentsClient",
		Methods: []capabilitycontract.Method{{
			Name:             "documents.archive",
			ClientMethod:     "archive",
			Effect:           "write",
			Execution:        "sync",
			TargetFields:     []string{"document_id"},
			TargetSchema:     testObjectSchema("document_id", map[string]any{"type": "string", "minLength": 1}),
			RequestTypeName:  "DocumentsArchiveRequest",
			ResponseTypeName: "DocumentsArchiveResponse",
			RequestSchema:    testObjectSchema("document_id", map[string]any{"type": "string", "minLength": 1}),
			ResponseSchema:   testObjectSchema("accepted", map[string]any{"type": "boolean"}),
		}},
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := capabilitycontract.Build(capabilitycontract.BuildRequest{
		Contract: contract, PublisherID: contract.PublisherID,
		ArtifactBaseRef: "capabilities/example/" + contractVersion,
		GeneratedAt:     time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC), SourceCommit: strings.Repeat("a", 40),
		MinReDevPluginVersion: "0.3.0", SignatureKeyID: "example-key", SignaturePolicyEpoch: "1", SignatureRevocationEpoch: "1",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := capabilitycontract.Verify(capabilitycontract.VerifyRequest{
		Bundle: bundle, ExpectedPin: bundle.Pin,
		TrustedKey:                capabilitycontract.TrustedKey{PublisherID: contract.PublisherID, KeyID: "example-key", PublicKey: publicKey, PolicyEpoch: "1", RevocationEpoch: "1"},
		CurrentReDevPluginVersion: "0.3.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func testObjectSchema(name string, child map[string]any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           map[string]any{name: child},
		"required":             []string{name},
	}
}
