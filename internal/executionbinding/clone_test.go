package executionbinding

import (
	"encoding/json"
	"testing"

	"github.com/floegence/redevplugin/pkg/capability"
	"github.com/floegence/redevplugin/pkg/capabilitycontract"
)

func TestCloneTrustedOwnsExecutionBindingContainers(t *testing.T) {
	contract := &capabilitycontract.Pin{ContractID: "documents"}
	binding := capability.ExecutionBinding{
		Contract: contract,
		Permissions: capability.PermissionEvidence{
			Required: []string{"documents.read"},
			Granted:  []string{"documents.read"},
		},
		Target: capability.TargetDescriptor{Fields: map[string]any{
			"selectors": []any{
				"title",
				map[string]any{"indexes": []any{json.Number("1"), 2.0}},
			},
		}},
	}

	cloned := CloneTrusted(binding)
	cloned.Contract.ContractID = "changed"
	cloned.Permissions.Required[0] = "changed"
	cloned.Permissions.Granted[0] = "changed"
	clonedSelectors := cloned.Target.Fields["selectors"].([]any)
	clonedSelectors[0] = "changed"
	clonedSelectors[1].(map[string]any)["indexes"].([]any)[0] = json.Number("2")

	if contract.ContractID != "documents" {
		t.Fatalf("contract pointer aliases clone: %q", contract.ContractID)
	}
	if binding.Permissions.Required[0] != "documents.read" || binding.Permissions.Granted[0] != "documents.read" {
		t.Fatalf("permission slices alias clone: %#v", binding.Permissions)
	}
	selectors := binding.Target.Fields["selectors"].([]any)
	if selectors[0] != "title" || selectors[1].(map[string]any)["indexes"].([]any)[0] != json.Number("1") {
		t.Fatalf("target containers alias clone: %#v", binding.Target.Fields)
	}
}

func TestCloneTrustedPreservesNilContainers(t *testing.T) {
	binding := capability.ExecutionBinding{
		Permissions: capability.PermissionEvidence{Required: nil, Granted: nil},
		Target:      capability.TargetDescriptor{Fields: nil},
	}
	cloned := CloneTrusted(binding)
	if cloned.Permissions.Required != nil || cloned.Permissions.Granted != nil || cloned.Target.Fields != nil {
		t.Fatalf("nil containers changed representation: %#v", cloned)
	}
}

func TestCloneTrustedPreservesNonNilEmptyContainers(t *testing.T) {
	binding := capability.ExecutionBinding{
		Permissions: capability.PermissionEvidence{Required: []string{}, Granted: []string{}},
		Target:      capability.TargetDescriptor{Fields: map[string]any{"items": []any{}}},
	}
	cloned := CloneTrusted(binding)
	if cloned.Permissions.Required == nil || cloned.Permissions.Granted == nil || cloned.Target.Fields == nil {
		t.Fatalf("non-nil containers changed representation: %#v", cloned)
	}
	if cloned.Target.Fields["items"].([]any) == nil {
		t.Fatalf("non-nil nested slice changed representation: %#v", cloned.Target.Fields)
	}
}

func TestCloneTrustedRejectsBrokenStoreInvariant(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("CloneTrusted() accepted a non-canonical store-owned value")
		}
	}()
	CloneTrusted(capability.ExecutionBinding{Target: capability.TargetDescriptor{Fields: map[string]any{"invalid": []string{"value"}}}})
}
