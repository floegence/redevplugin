package storage

import (
	"reflect"
	"testing"
)

func TestStorageKindsAreStable(t *testing.T) {
	if StoreFiles != "files" || StoreKV != "kv" || StoreSQLite != "sqlite" {
		t.Fatalf("storage kind values changed: %q %q %q", StoreFiles, StoreKV, StoreSQLite)
	}
}

func TestStorageDomainRequestsDoNotSerializeResourceOwners(t *testing.T) {
	for _, request := range []any{
		FileReadRequest{}, FileWriteRequest{}, FileDeleteRequest{}, FileListRequest{},
		KVGetRequest{}, KVPutRequest{}, KVDeleteRequest{}, KVListRequest{},
		SQLiteExecRequest{}, SQLiteQueryRequest{},
	} {
		typeOf := reflect.TypeOf(request)
		field, ok := typeOf.FieldByName("ResourceScope")
		if !ok {
			t.Fatalf("%s has no ResourceScope field", typeOf.Name())
		}
		if got := field.Tag.Get("json"); got != "-" {
			t.Fatalf("%s ResourceScope JSON tag = %q, want -", typeOf.Name(), got)
		}
	}
}
