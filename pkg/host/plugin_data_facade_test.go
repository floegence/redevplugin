package host

import (
	"errors"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/plugindata"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

func TestPluginDataFileFacadeDerivesExactSessionResourceScope(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, "plugini_data_facade", buildWorkerStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	write, err := h.WritePluginDataFile(hostTestContext(), WritePluginDataFileRequest{
		PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser,
		StoreID: "workspace", Path: "notes/test.txt", Data: []byte("host-owned"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if write.SizeBytes != int64(len("host-owned")) {
		t.Fatalf("WritePluginDataFile() = %#v", write)
	}
	read, err := h.ReadPluginDataFile(hostTestContext(), ReadPluginDataFileRequest{
		PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser,
		StoreID: "workspace", Path: "notes/test.txt", MaxBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Data) != "host-owned" {
		t.Fatalf("ReadPluginDataFile() data = %q", read.Data)
	}
	if _, err := h.ReadPluginDataFile(hostTestContext(), ReadPluginDataFileRequest{
		PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeEnvironment,
		StoreID: "workspace", Path: "notes/test.txt", MaxBytes: 1024,
	}); !errors.Is(err, plugindata.ErrStorageScopeMismatch) {
		t.Fatalf("ReadPluginDataFile(wrong scope) error = %v, want ErrStorageScopeMismatch", err)
	}
}

func TestInspectPluginDataReturnsHostOwnedFacts(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	installed, err := ImportLocalPackageBytes(hostTestContext(), h, "plugini_data_inspect", buildWorkerStorageFixturePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.EnablePlugin(hostTestContext(), EnableRequest{PluginInstanceID: installed.PluginInstanceID, ExpectedManagementRevision: installed.ManagementRevision}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.WritePluginDataFile(hostTestContext(), WritePluginDataFileRequest{
		PluginInstanceID: installed.PluginInstanceID, Scope: sessionctx.ScopeUser,
		StoreID: "workspace", Path: "inspect.txt", Data: []byte("facts"),
	}); err != nil {
		t.Fatal(err)
	}
	inspection, err := h.InspectPluginData(hostTestContext(), InspectPluginDataRequest{PluginInstanceID: installed.PluginInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Bindings) != 1 || inspection.Bindings[0].PluginInstanceID != installed.PluginInstanceID {
		t.Fatalf("bindings = %#v", inspection.Bindings)
	}
	if len(inspection.Namespaces) == 0 {
		t.Fatal("InspectPluginData() returned no namespaces")
	}
	foundWorkspace := false
	for _, namespace := range inspection.Namespaces {
		if namespace.StoreID == "workspace" {
			foundWorkspace = true
			if namespace.UsageBytes != int64(len("facts")) || namespace.Scope != string(sessionctx.ScopeUser) {
				t.Fatalf("workspace namespace = %#v", namespace)
			}
		}
	}
	if !foundWorkspace {
		t.Fatalf("namespaces = %#v", inspection.Namespaces)
	}
	if inspection.TotalUsageBytes < int64(len("facts")) {
		t.Fatalf("total usage = %d", inspection.TotalUsageBytes)
	}
}
