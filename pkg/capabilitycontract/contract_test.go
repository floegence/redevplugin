package capabilitycontract

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRequiresAsyncConfirmationAndEventPolicy(t *testing.T) {
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
	t.Run("confirmation preflight", func(t *testing.T) {
		contract := testContract()
		contract.Methods[1].Confirmation.PreflightMethod = "documents.list"
		contract.Methods[1].Confirmation.PlanHashRequired = true
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "preflight_only") {
			t.Fatalf("Validate() error = %v, want preflight-only rejection", err)
		}
		contract.Methods[0].PreflightOnly = true
		if err := Validate(contract); err != nil {
			t.Fatalf("Validate() rejected valid preflight contract: %v", err)
		}
	})
}

func TestGenerateTypeScriptPreservesContractPolicy(t *testing.T) {
	clientBytes, err := GenerateTypeScript(testContract())
	if err != nil {
		t.Fatal(err)
	}
	client := string(clientBytes)
	for _, expected := range []string{
		"ExampleDocumentsClient", "DocumentsArchiveRequest", "DOCUMENT_NOT_FOUND",
		"cancelable: true", "documents.watch",
	} {
		if !strings.Contains(client, expected) {
			t.Fatalf("generated client missing %q", expected)
		}
	}
}

func TestKnownContractRegistryRequiresExactIdentityAndHash(t *testing.T) {
	known, err := NewKnownContract(testContract())
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.Add(known); err != nil {
		t.Fatal(err)
	}
	got, err := registry.Require(known.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if got.Contract.ContractID != known.Contract.ContractID {
		t.Fatalf("contract id = %q", got.Contract.ContractID)
	}
	tampered := known.Pin
	tampered.ArtifactSHA256 = strings.Repeat("0", 64)
	if _, err := registry.Require(tampered); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("tampered hash error = %v, want ErrIdentityMismatch", err)
	}
}

func TestKnownContractRegistryRejectsForgedOrMutatedContracts(t *testing.T) {
	known, err := NewKnownContract(testContract())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := NewKnownContract(testContract())
	if err != nil {
		t.Fatal(err)
	}
	forged.Contract.Methods[0].Name = "documents.forged"
	if err := NewRegistry().Add(forged); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("forged Add() error = %v, want ErrIdentityMismatch", err)
	}

	registry := NewRegistry()
	if err := registry.Add(known); err != nil {
		t.Fatal(err)
	}
	known.Contract.Methods[0].Name = "documents.mutated"
	stored, err := registry.Require(known.Pin)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Contract.Methods[0].Name != "documents.list" {
		t.Fatalf("registry retained caller mutation: %q", stored.Contract.Methods[0].Name)
	}
}

func TestKnownContractPreservesEmptyCollectionIdentity(t *testing.T) {
	contract := testContract()
	contract.Methods[0].TargetFields = []string{}
	known, err := NewKnownContract(contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewRegistry().Add(known); err != nil {
		t.Fatalf("Add() rejected an unchanged known contract: %v", err)
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

func testContract() Contract {
	return Contract{
		SchemaVersion: SchemaVersion, ContractID: "example.documents.v1", ContractVersion: "1.0.0",
		PublisherID: "example.publisher", CapabilityID: "example.capability.documents", CapabilityVersion: "1.0.0",
		ClientName: "ExampleDocumentsClient",
		Errors: []BusinessError{{Code: "DOCUMENT_NOT_FOUND", Message: "Document not found", DetailsSchema: objectSchema(map[string]any{
			"document_id": map[string]any{"type": "string", "minLength": 1},
		}, []string{"document_id"})}},
		Methods: []Method{
			{
				Name: "documents.list", ClientMethod: "list", Effect: "read", Execution: "sync",
				RequiredPermissions: []string{"documents.read"}, TargetFields: []string{"workspace_id"},
				TargetSchema:    objectSchema(map[string]any{"workspace_id": map[string]any{"type": "string"}}, []string{"workspace_id"}),
				RequestTypeName: "DocumentsListRequest", ResponseTypeName: "DocumentsListResponse",
				RequestSchema:  objectSchema(map[string]any{"workspace_id": map[string]any{"type": "string"}}, []string{"workspace_id"}),
				ResponseSchema: objectSchema(map[string]any{"documents": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, []string{"documents"}),
			},
			{
				Name: "documents.archive", ClientMethod: "archive", Effect: "write", Execution: "operation",
				RequiredPermissions: []string{"documents.manage"}, TargetFields: []string{"document_id"},
				TargetSchema:    objectSchema(map[string]any{"document_id": map[string]any{"type": "string"}}, []string{"document_id"}),
				RequestTypeName: "DocumentsArchiveRequest", ResponseTypeName: "DocumentsArchiveResponse",
				RequestSchema:  objectSchema(map[string]any{"document_id": map[string]any{"type": "string"}}, []string{"document_id"}),
				ResponseSchema: objectSchema(map[string]any{"accepted": map[string]any{"type": "boolean"}}, []string{"accepted"}),
				Confirmation:   &Confirmation{Mode: "required", RequestHashFields: []string{"document_id"}},
				CancelPolicy:   &CancelPolicy{Cancelable: true, DisableBehavior: "cancel", UninstallBehavior: "cancel_then_block_delete", AckTimeoutMS: 1000},
				Quota:          Quota{MaxConcurrent: 2, MaxDurationMS: 30000},
			},
			{
				Name: "documents.watch", ClientMethod: "watch", Effect: "read", Execution: "subscription",
				RequiredPermissions: []string{"documents.read"}, TargetFields: []string{"workspace_id"},
				TargetSchema:    objectSchema(map[string]any{"workspace_id": map[string]any{"type": "string"}}, []string{"workspace_id"}),
				RequestTypeName: "DocumentsWatchRequest", ResponseTypeName: "DocumentsWatchResponse",
				RequestSchema:  objectSchema(map[string]any{"workspace_id": map[string]any{"type": "string"}}, []string{"workspace_id"}),
				ResponseSchema: objectSchema(map[string]any{"watching": map[string]any{"type": "boolean"}}, []string{"watching"}),
				EventTypeName:  "DocumentsWatchEvent", EventSchema: objectSchema(map[string]any{"document_id": map[string]any{"type": "string"}}, []string{"document_id"}),
				CancelPolicy: &CancelPolicy{Cancelable: true, DisableBehavior: "cancel", UninstallBehavior: "cancel_then_block_delete", AckTimeoutMS: 1000},
				Quota:        Quota{MaxConcurrent: 4, MaxStreamBytes: 1048576},
			},
		},
	}
}

func objectSchema(properties map[string]any, required []string) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}
