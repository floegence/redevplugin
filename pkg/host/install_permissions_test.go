package host

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/capability"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"github.com/floegence/redevplugin/v3/pkg/execution"
	"github.com/floegence/redevplugin/v3/pkg/mutation"
	"github.com/floegence/redevplugin/v3/pkg/registry"
)

func inspectPermissionPackage(t *testing.T) (*Host, ExternalPackageInspection) {
	t.Helper()
	contract, err := fixtureCapabilityContract("example.capability.echo")
	if err != nil {
		t.Fatal(err)
	}
	empty := map[string]any{"type": "object", "additionalProperties": false}
	contract.Methods = []capabilitycontract.Method{fixtureContractMethod("agent.begin", "execute", "sync", []string{"fs.workspace.read"}, nil, empty, empty)}
	known := verifyFixtureCapabilityContract(t, contract)
	h, _, _ := newTestHostWithOptions(t, testHostOptions{capabilityContract: &known, capabilityAdapter: &recordingCapabilityAdapter{result: capability.Result{Data: map[string]any{}}}})
	pkg := surfaceMethodsFixtureWith(t, func(m map[string]any) { m["permissions"] = append(m["permissions"].([]any), "fs.workspace.read") }, known)
	configureExternalPackageTestModule(h, &externalPackageTestStage{pkg: readTestPackage(t, pkg)})
	inspection, err := h.InspectUploadedExternalPackage(hostTestContext(), InspectUploadedExternalPackageRequest{Intent: ExternalPackageIntent{Action: "install"}, Package: strings.NewReader("package"), DeclaredSize: 7})
	if err != nil {
		t.Fatal(err)
	}
	return h, inspection
}

func awaitPermissionInstall(t *testing.T, h *Host, request StartInspectedInstallRequest) InspectedInstallOperation {
	t.Helper()
	if _, err := h.StartInspectedInstall(hostTestContext(), request); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(3 * time.Second); ; {
		op, err := h.GetInspectedInstall(hostTestContext(), request.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if op.Execution.Status != execution.StatusRunning {
			if op.Execution.Status != execution.StatusCompleted || op.MutationOutcome != mutation.OutcomeCommitted {
				t.Fatalf("install: %+v", op)
			}
			return op
		}
		if time.Now().After(end) {
			t.Fatal("install did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInspectedInstallCommitsExplicitReviewedPermissions(t *testing.T) {
	h, inspection := inspectPermissionPackage(t)
	// Exercise the public JSON request before adding the contract: older code
	// silently discards this choice and leaves the installed plugin unusable.
	raw, _ := json.Marshal(map[string]any{"request_id": "allow-and-install", "inspection_id": inspection.InspectionID, "expected_package_sha256": inspection.InspectedHashes.PackageSHA256, "approved_permissions": []string{"fs.workspace.read"}})
	var request StartInspectedInstallRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	op := awaitPermissionInstall(t, h, request)
	grants, err := h.ListPermissionGrants(hostTestContext(), ListPermissionGrantsRequest{PluginInstanceID: op.Execution.PluginInstanceID})
	if err != nil || len(grants) != 1 || grants[0].PermissionID != "fs.workspace.read" {
		t.Fatalf("reviewed permission was not committed with installation: %+v %v", grants, err)
	}
	if _, err := h.CallInstalledCapability(surfaceMethodTestContext(), InstalledCapabilityRequest{PluginInstanceID: op.Execution.PluginInstanceID, Method: "agent.begin"}); err != nil {
		t.Fatalf("installed capability is unusable after consent: %v", err)
	}
	request.ApprovedPermissions = nil
	if _, err := h.StartInspectedInstall(hostTestContext(), request); !errors.Is(err, ErrExternalPackageConfirmation) {
		t.Fatalf("changed consent reused original request: %v", err)
	}
	request.ApprovedPermissions = []string{"fs.workspace.read"}
	if _, err := h.StartInspectedInstall(hostTestContext(), request); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(op.ApprovedPermissions, request.ApprovedPermissions) {
		t.Fatal("receipt lost explicit consent")
	}
}

func TestInspectedInstallRejectsUnreviewedOrAutomaticGrants(t *testing.T) {
	for _, ids := range [][]string{{"undeclared"}, {"fs.selected.read"}, {"fs.workspace.read", "fs.workspace.read"}, {" fs.workspace.read"}} {
		t.Run(strings.Join(ids, ","), func(t *testing.T) {
			h, inspected := inspectPermissionPackage(t)
			_, err := h.StartInspectedInstall(hostTestContext(), StartInspectedInstallRequest{RequestID: "invalid", InspectionID: inspected.InspectionID, ExpectedPackageSHA256: inspected.InspectedHashes.PackageSHA256, ApprovedPermissions: ids})
			if err == nil {
				t.Fatal("invalid consent accepted")
			}
			if _, err := h.GetInspectedInstall(hostTestContext(), "invalid"); !errors.Is(err, ErrInspectedInstallNotFound) {
				t.Fatal("invalid choice created operation", err)
			}
		})
	}
	h, inspected := inspectPermissionPackage(t)
	_, err := h.StartInspectedInstall(hostTestContext(), StartInspectedInstallRequest{RequestID: "automatic", InspectionID: inspected.InspectionID, ExpectedPackageSHA256: inspected.InspectedHashes.PackageSHA256, Automatic: true, ApprovedPermissions: []string{"fs.workspace.read"}})
	if !errors.Is(err, ErrExternalPackageRequestInvalid) {
		t.Fatal("automatic consent accepted", err)
	}
}

type denyInstallGrant struct{}

func (denyInstallGrant) Authorize(_ context.Context, req AuthorizationRequest) error {
	if req.Action == ManagementActionGrantPermission {
		return ErrActionDenied
	}
	return nil
}

func TestInspectedInstallRechecksGrantAuthorityAndProtectsInspection(t *testing.T) {
	h, inspected := inspectPermissionPackage(t)
	inspected.GrantablePermissions[0] = "undeclared"
	request := StartInspectedInstallRequest{RequestID: "denied", InspectionID: inspected.InspectionID, ExpectedPackageSHA256: inspected.InspectedHashes.PackageSHA256, ApprovedPermissions: []string{"undeclared"}}
	if _, err := h.StartInspectedInstall(hostTestContext(), request); !errors.Is(err, ErrExternalPackageConfirmation) {
		t.Fatal("caller changed retained inspection", err)
	}
	request.ApprovedPermissions = []string{"fs.workspace.read"}
	h.adapters.Authorization = denyInstallGrant{}
	if _, err := h.StartInspectedInstall(hostTestContext(), request); !errors.Is(err, ErrActionDenied) {
		t.Fatal("changed authorization accepted", err)
	}
	if _, err := h.getPluginRecord(hostTestContext(), inspected.Intent.PluginInstanceID); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("denied permission still installed package", err)
	}
}

func TestInspectedInstallWithoutConsentGrantsNothing(t *testing.T) {
	h, inspected := inspectPermissionPackage(t)
	op := awaitPermissionInstall(t, h, StartInspectedInstallRequest{RequestID: "install-only", InspectionID: inspected.InspectionID, ExpectedPackageSHA256: inspected.InspectedHashes.PackageSHA256})
	grants, err := h.ListPermissionGrants(hostTestContext(), ListPermissionGrantsRequest{PluginInstanceID: op.Execution.PluginInstanceID})
	if err != nil || len(grants) != 0 {
		t.Fatal("implicit grants", grants, err)
	}
}
