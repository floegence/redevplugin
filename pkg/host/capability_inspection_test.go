package host

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestCapabilityInspectionDistinguishesDeclarationsGrantsAndPolicyWithoutExecution(t *testing.T) {
	for _, declared := range []bool{false, true} {
		t.Run(map[bool]string{false: "binding-only", true: "declared"}[declared], func(t *testing.T) {
			contract, err := fixtureCapabilityContract("example.capability.echo")
			if err != nil {
				t.Fatal(err)
			}
			empty := fixtureClosedObject(nil, nil)
			contract.Methods = []capabilitycontract.Method{fixtureContractMethod("agent.begin", "execute", "sync", []string{"fs.workspace.read"}, nil, empty, empty)}
			known := verifyFixtureCapabilityContract(t, contract)
			adapter := &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}
			h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityContract: &known, capabilityAdapter: adapter})
			pkg := surfaceMethodsFixtureWith(t, func(m map[string]any) {
				m["permissions"] = append(m["permissions"].([]any), "fs.workspace.read")
				if !declared {
					methods := []any{}
					for _, item := range m["methods"].([]any) {
						if item.(map[string]any)["method"] != "agent.begin" {
							methods = append(methods, item)
						}
					}
					m["methods"] = methods
				}
			}, known)
			record := installAndEnablePlugin(t, h, pkg)
			request := GetPermissionRequirementsRequest{PluginInstanceID: record.PluginInstanceID}
			inspect := func() CapabilityMethodInspection {
				t.Helper()
				before, err := h.getAuthorizationSnapshot(hostTestContext(), record.PluginInstanceID)
				if err != nil {
					t.Fatal(err)
				}
				result, err := h.InspectPluginCapabilities(hostTestContext(), request)
				if err != nil {
					t.Fatal(err)
				}
				after, err := h.getAuthorizationSnapshot(hostTestContext(), record.PluginInstanceID)
				if err != nil || !reflect.DeepEqual(before, after) || adapter.calls != 0 {
					t.Fatal("inspection changed canonical state or dispatched work", err)
				}
				if result.PluginInstanceID != record.PluginInstanceID || result.PackageSHA256 != record.PackageHash || result.ObservedAt.IsZero() || len(result.Bindings) != 1 || !result.Bindings[0].AdapterRegistered || !result.Bindings[0].ContractAvailable {
					t.Fatalf("incomplete evidence: %+v", result)
				}
				for _, method := range result.Bindings[0].Methods {
					if method.Method == "agent.begin" {
						return method
					}
				}
				t.Fatal("published method omitted")
				return CapabilityMethodInspection{}
			}
			method := inspect()
			if method.Declared != declared || method.Declaration.Route.TargetMethod != method.Method {
				t.Fatalf("declaration evidence: %+v", method)
			}
			if !declared {
				if !slices.Equal(method.Blockers, []string{"method_not_declared"}) || len(method.MissingPermissions) != 0 {
					t.Fatalf("undeclared method incorrectly diagnosed as missing consent: %+v", method)
				}
				return
			}
			if !slices.Equal(method.MissingPermissions, []string{"fs.workspace.read"}) || !slices.Contains(method.Blockers, "permission_required") {
				t.Fatalf("grant diagnosis: %+v", method)
			}
			rev := mustAuthorizationRevisions(t, h, record.PluginInstanceID)
			if _, err := h.GrantPermission(hostTestContext(), GrantPermissionRequest{PluginInstanceID: record.PluginInstanceID, PermissionID: "fs.workspace.read", ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
				t.Fatal(err)
			}
			if method = inspect(); len(method.Blockers) != 0 || len(method.MissingPermissions) != 0 {
				t.Fatalf("granted method: %+v", method)
			}
			rev = mustAuthorizationRevisions(t, h, record.PluginInstanceID)
			if _, err := h.PutSecurityPolicy(hostTestContext(), PutSecurityPolicyRequest{PluginInstanceID: record.PluginInstanceID, DeniedMethods: []string{"agent.begin"}, AllowedPermissions: []string{"fs.workspace.read"}, ExpectedPolicyRevision: rev.PolicyRevision, ExpectedManagementRevision: rev.ManagementRevision, ExpectedRevokeEpoch: rev.RevokeEpoch}); err != nil {
				t.Fatal(err)
			}
			if method = inspect(); len(method.MissingPermissions) != 0 || len(method.Blockers) != 1 || method.Blockers[0] != "method_denied" {
				t.Fatalf("policy denial confused with consent: %+v", method)
			}
			foreign, _ := sessionctx.FromContext(hostTestContext())
			foreign.OwnerEnvHash = "another-environment"
			for _, ctx := range []context.Context{context.Background(), sessionctx.WithContext(context.Background(), foreign)} {
				if result, err := h.InspectPluginCapabilities(ctx, request); err == nil || result.PluginInstanceID != "" {
					t.Fatal("inspection disclosed another scope")
				}
			}
			cancelled, cancel := context.WithCancel(hostTestContext())
			cancel()
			if _, err := h.InspectPluginCapabilities(cancelled, request); err == nil {
				t.Fatal("cancelled inspection succeeded")
			}
			h.adapters.Capabilities = capability.NewRegistry()
			if err := h.adapters.Capabilities.AddContract(known); err != nil {
				t.Fatal(err)
			}
			result, err := h.InspectPluginCapabilities(hostTestContext(), request)
			if err != nil || result.Bindings[0].AdapterRegistered || !result.Bindings[0].ContractAvailable {
				t.Fatal("contract availability confused with adapter registration", result, err)
			}
			raw, _ := json.Marshal(result)
			if !json.Valid(raw) {
				t.Fatal("inspection is not JSON")
			}
		})
	}
}
