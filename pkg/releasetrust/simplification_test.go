package releasetrust

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReleaseTrustUsesOnlyDocumentTransport(t *testing.T) {
	adapterType := reflect.TypeOf(ReleaseTrustAdapters{})
	if adapterType.NumField() != 1 || adapterType.Field(0).Name != "Documents" {
		t.Fatalf("ReleaseTrustAdapters fields = %v; want Documents only", adapterFieldNames(adapterType))
	}
	for _, name := range []string{"trusted_time.go", "state.go", "lease.go", "activation_recovery.go"} {
		if _, err := os.Stat(filepath.Join(".", name)); !os.IsNotExist(err) {
			t.Fatalf("obsolete release trust owner %s still exists", name)
		}
	}
}

func adapterFieldNames(value reflect.Type) []string {
	result := make([]string, value.NumField())
	for index := range result {
		result[index] = value.Field(index).Name
	}
	return result
}
