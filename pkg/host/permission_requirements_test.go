package host

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func TestBuildPluginPermissionRequirementsResolvesOneContractOnceForManyMethods(t *testing.T) {
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	contract.Methods = nil
	pluginMethods := make([]manifest.MethodSpec, 0, 52)
	permissions := []string{"containers.delete", "containers.execute", "containers.images.write", "containers.read"}
	for index := range 52 {
		name := fmt.Sprintf("containers.action%d", index)
		contract.Methods = append(contract.Methods, fixtureContractMethod(
			name,
			"read",
			"sync",
			[]string{permissions[index%len(permissions)]},
			nil,
			fixtureClosedObject(nil, nil),
			fixtureClosedObject(nil, nil),
		))
		pluginMethods = append(pluginMethods, manifest.MethodSpec{
			Method: name,
			Route: manifest.MethodRouteSpec{
				Kind:         manifest.MethodRouteCapability,
				BindingID:    "containers",
				TargetMethod: name,
			},
		})
	}
	known := verifyFixtureCapabilityContract(t, contract)
	record := registry.PluginRecord{
		Manifest: manifest.Manifest{
			CapabilityBindings: []manifest.CapabilityBinding{{BindingID: "containers", Contract: known.Pin}},
			Methods:            pluginMethods,
		},
		CapabilityContracts: []capabilitycontract.Pin{known.Pin},
	}
	requireCalls := 0
	require := func(pins []capabilitycontract.Pin, binding manifest.CapabilityBinding) (capabilitycontract.KnownContract, error) {
		requireCalls++
		if !slices.Contains(pins, binding.Contract) || binding.Contract != known.Pin {
			return capabilitycontract.KnownContract{}, capabilitycontract.ErrIdentityMismatch
		}
		return known, nil
	}

	projection, err := buildPluginPermissionRequirements(record, require)
	if err != nil {
		t.Fatal(err)
	}
	if requireCalls != 1 {
		t.Fatalf("contract resolutions = %d, want 1 for 52 methods", requireCalls)
	}
	if len(projection.methods) != 52 || len(projection.contracts) != 1 || len(projection.contracts[0].Methods) != 52 {
		t.Fatalf("permission requirement projection = %#v", projection)
	}
	if !slices.Equal(projection.requiredPermissions, permissions) {
		t.Fatalf("required permissions = %#v, want %#v", projection.requiredPermissions, permissions)
	}
}

func TestBuildPluginPermissionRequirementsResolvesEachUniqueContractOnce(t *testing.T) {
	echo := fixtureVerifiedCapabilityContract(t, "example.capability.echo")
	tasks := fixtureVerifiedCapabilityContract(t, "example.capability.tasks")
	record := registry.PluginRecord{
		Manifest: manifest.Manifest{
			CapabilityBindings: []manifest.CapabilityBinding{
				{BindingID: "echo", Contract: echo.Pin},
				{BindingID: "tasks", Contract: tasks.Pin},
			},
			Methods: []manifest.MethodSpec{
				{Method: "echo.ping", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "echo", TargetMethod: "echo.ping"}},
				{Method: "danger.run", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "echo", TargetMethod: "danger.run"}},
				{Method: "tasks.list", Route: manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "tasks", TargetMethod: "tasks.list"}},
			},
		},
		CapabilityContracts: []capabilitycontract.Pin{echo.Pin, tasks.Pin},
	}
	known := map[capabilitycontract.Pin]capabilitycontract.KnownContract{echo.Pin: echo, tasks.Pin: tasks}
	calls := map[capabilitycontract.Pin]int{}

	projection, err := buildPluginPermissionRequirements(record, func(
		pins []capabilitycontract.Pin,
		binding manifest.CapabilityBinding,
	) (capabilitycontract.KnownContract, error) {
		calls[binding.Contract]++
		if !slices.Contains(pins, binding.Contract) {
			return capabilitycontract.KnownContract{}, capabilitycontract.ErrIdentityMismatch
		}
		return known[binding.Contract], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls[echo.Pin] != 1 || calls[tasks.Pin] != 1 || len(calls) != 2 {
		t.Fatalf("contract resolutions = %#v, want once per unique contract", calls)
	}
	if len(projection.contracts) != 2 || len(projection.methods) != 3 {
		t.Fatalf("permission requirement projection = %#v", projection)
	}
}

func TestBuildPluginPermissionRequirementsFailsClosed(t *testing.T) {
	known := fixtureVerifiedCapabilityContract(t, "example.capability.echo")
	base := registry.PluginRecord{
		Manifest: manifest.Manifest{
			CapabilityBindings: []manifest.CapabilityBinding{{BindingID: "echo", Contract: known.Pin}},
			Methods: []manifest.MethodSpec{{
				Method: "echo.ping",
				Route:  manifest.MethodRouteSpec{Kind: manifest.MethodRouteCapability, BindingID: "echo", TargetMethod: "echo.ping"},
			}},
		},
		CapabilityContracts: []capabilitycontract.Pin{known.Pin},
	}
	validResolver := func(_ []capabilitycontract.Pin, _ manifest.CapabilityBinding) (capabilitycontract.KnownContract, error) {
		return known, nil
	}

	tests := []struct {
		name    string
		record  registry.PluginRecord
		resolve pinnedCapabilityContractResolver
		want    string
	}{
		{
			name: "missing binding",
			record: func() registry.PluginRecord {
				value := base
				value.Manifest.CapabilityBindings = nil
				return value
			}(),
			resolve: validResolver,
			want:    "is not declared",
		},
		{
			name:   "unregistered pin",
			record: base,
			resolve: func(_ []capabilitycontract.Pin, _ manifest.CapabilityBinding) (capabilitycontract.KnownContract, error) {
				return capabilitycontract.KnownContract{}, capabilitycontract.ErrIdentityMismatch
			},
			want: capabilitycontract.ErrIdentityMismatch.Error(),
		},
		{
			name: "missing method",
			record: func() registry.PluginRecord {
				value := base
				value.Manifest.Methods = append([]manifest.MethodSpec(nil), base.Manifest.Methods...)
				value.Manifest.Methods[0].Route.TargetMethod = "echo.missing"
				return value
			}(),
			resolve: validResolver,
			want:    "is not published",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildPluginPermissionRequirements(test.record, test.resolve)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("buildPluginPermissionRequirements() error = %v, want containing %q", err, test.want)
			}
			if test.name == "unregistered pin" && !errors.Is(err, capabilitycontract.ErrIdentityMismatch) {
				t.Fatalf("error = %v, want identity mismatch", err)
			}
		})
	}
}
