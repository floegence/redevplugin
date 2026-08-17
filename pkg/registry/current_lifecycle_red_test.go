package registry

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCurrentLifecycleSourceHasOnlyEnabledAndDisabledByUser(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	root := filepath.Dir(file)
	for _, name := range []string{"registry.go", "external_package.go"} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, retired := range []string{"EnableDisabled             ", "EnableDisabledByPolicy", "EnableDisabledIncompatible", "disabled_by_policy", "disabled_incompatible"} {
			if strings.Contains(text, retired) {
				t.Fatalf("current lifecycle source %s still contains retired state %q", name, retired)
			}
		}
		for _, retired := range []string{"PackageSourceLegacyRegistry", "legacy_registry"} {
			if strings.Contains(text, retired) {
				t.Fatalf("current registry source %s still contains retired source fallback %q", name, retired)
			}
		}
	}
}

func TestCurrentRegistryOmitsRuntimeCompatibilityProjection(t *testing.T) {
	for _, value := range []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "PluginRecord", typeOf: reflect.TypeOf(PluginRecord{})},
		{name: "PluginVersion", typeOf: reflect.TypeOf(PluginVersion{})},
	} {
		if _, exists := value.typeOf.FieldByName("RuntimeRequirement"); exists {
			t.Fatalf("%s still exposes the retired RuntimeRequirement compatibility projection", value.name)
		}
	}
}
