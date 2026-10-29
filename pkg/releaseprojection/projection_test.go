package releaseprojection

import (
	"reflect"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func TestWorkerSecuritySummaryUsesExplicitMethodCeilings(t *testing.T) {
	read := []manifest.PermissionID{manifest.PermissionFSEnvironmentRead}
	empty := []manifest.PermissionID{}
	value := manifest.Manifest{Permissions: []manifest.PermissionID{manifest.PermissionFSEnvironmentRead, manifest.PermissionFSEnvironmentWrite}, Methods: []manifest.MethodSpec{
		{Method: "read", Permissions: read, Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "worker"}},
		{Method: "local", Permissions: empty, Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "worker"}},
		{Method: "existing", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteWorker, WorkerID: "worker"}},
	}}
	summary, err := BuildExternalPackageSecuritySummaryFromContracts(value, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"read": {"fs.environment.read"}, "local": {}, "existing": {"fs.environment.read", "fs.environment.write"}}
	for _, method := range summary.Methods {
		if !reflect.DeepEqual(method.RequiredPermissions, want[method.Method]) {
			t.Fatalf("%s permissions = %#v", method.Method, method.RequiredPermissions)
		}
	}
}

func TestBuildSecuritySummaryFromExactCapabilityContract(t *testing.T) {
	contract, err := capabilitycontract.NewKnownContract(capabilitycontract.Contract{
		SchemaVersion:     capabilitycontract.SchemaVersion,
		ContractID:        "example.resources",
		ContractVersion:   "1.0.0",
		PublisherID:       "example.publisher",
		CapabilityID:      "example.resources",
		CapabilityVersion: "1.0.0",
		ClientName:        "ExampleResourcesClient",
		Methods: []capabilitycontract.Method{{
			Name: "resources.list", ClientMethod: "listResources", Effect: "read", Execution: "sync",
			RequiredPermissions: []string{"resources.read"}, TargetFields: []string{},
			TargetSchema: map[string]any{"type": "object", "additionalProperties": false}, RequestTypeName: "ListRequest", ResponseTypeName: "ListResponse",
			RequestSchema: map[string]any{"type": "object", "additionalProperties": false}, ResponseSchema: map[string]any{"type": "object", "additionalProperties": false},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestValue := manifest.Manifest{
		CapabilityBindings: []manifest.CapabilityBinding{{BindingID: "resources", Contract: contract.Pin}},
		Methods: []manifest.MethodSpec{{
			Method: "resources.list", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "resources", TargetMethod: "resources.list"},
		}},
	}
	summary, err := BuildExternalPackageSecuritySummaryFromContracts(manifestValue, []capabilitycontract.KnownContract{contract})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Permissions) != 1 || summary.Permissions[0].PermissionID != "resources.read" || len(summary.Permissions[0].Methods) != 1 {
		t.Fatalf("permissions = %#v", summary.Permissions)
	}
	if summary.Methods[0].RequiredPermissions[0] != "resources.read" {
		t.Fatalf("method projection = %#v", summary.Methods[0])
	}
}

func TestBuildSecuritySummaryFromContractsRejectsUnresolvedPin(t *testing.T) {
	manifestValue := manifest.Manifest{
		CapabilityBindings: []manifest.CapabilityBinding{{BindingID: "resources", Contract: capabilitycontract.Pin{
			PublisherID: "example.publisher", ContractID: "example.resources", ContractVersion: "1.0.0", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}},
	}
	if _, err := BuildExternalPackageSecuritySummaryFromContracts(manifestValue, nil); err == nil {
		t.Fatal("unresolved capability contract was accepted")
	}
}
