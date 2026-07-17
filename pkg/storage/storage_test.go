package storage

import "testing"

func TestStorageKindsAreStable(t *testing.T) {
	if StoreFiles != "files" || StoreKV != "kv" || StoreSQLite != "sqlite" {
		t.Fatalf("storage kind values changed: %q %q %q", StoreFiles, StoreKV, StoreSQLite)
	}
}
