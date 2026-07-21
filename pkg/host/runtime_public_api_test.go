package host_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/floegence/redevplugin/pkg/host"
)

func TestRuntimeCapabilitiesExposeNoInjectableState(t *testing.T) {
	assertNoExportedFields(t, reflect.TypeFor[host.VerifiedExecutable]())
	assertNoExportedFields(t, reflect.TypeFor[host.RuntimeModule]())

	configType := reflect.TypeFor[host.Config]()
	runtimeField, ok := configType.FieldByName("Runtime")
	if !ok || runtimeField.Type != reflect.TypeFor[*host.RuntimeModule]() {
		t.Fatalf("Config.Runtime type = %v, want *host.RuntimeModule", runtimeField.Type)
	}

	constructor := reflect.TypeOf(host.NewRuntimeModule)
	if constructor.NumIn() != 2 || constructor.In(0) != reflect.TypeFor[*host.VerifiedExecutable]() || constructor.In(1) != reflect.TypeFor[host.RuntimeModuleOptions]() ||
		constructor.NumOut() != 2 || constructor.Out(0) != reflect.TypeFor[*host.RuntimeModule]() || constructor.Out(1) != reflect.TypeFor[error]() {
		t.Fatalf("NewRuntimeModule signature changed: %v", constructor)
	}
}

func TestLegacyPublicRuntimeClientPackageIsAbsent(t *testing.T) {
	repositoryRoot := runtimePublicAPITestRepositoryRoot(t)
	command := exec.Command("go", "list", "github.com/floegence/redevplugin/pkg/runtimeclient")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("legacy public runtime package remains importable: %s", output)
	}
}

func assertNoExportedFields(t *testing.T, value reflect.Type) {
	t.Helper()
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if field.IsExported() {
			t.Fatalf("%s exposes injectable field %s", value, field.Name)
		}
	}
}

func runtimePublicAPITestRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve runtime API test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
