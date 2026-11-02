package plugindata

import (
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"testing"
)

func TestSQLiteBatchRollsBackOnStatementFailure(t *testing.T) {
	store, _, shape := newInternalStore(t)
	ctx := internalTestContext()
	shape.Namespaces = append(shape.Namespaces, Namespace{ID: "db", Kind: NamespaceSQLite, Scope: "user", SchemaVersion: 1, QuotaBytes: 1 << 20, QuotaFiles: 8})
	installInternalStore(t, store, ctx, "plugini_test", shape)
	req := storage.SQLiteExecRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "db", SQL: "CREATE TABLE notes (id INTEGER PRIMARY KEY)"}
	if _, err := store.ExecSQLite(ctx, req); err != nil {
		t.Fatal(err)
	}
	req.SQL = ""
	req.Statements = []storage.SQLiteStatement{{SQL: "INSERT INTO notes VALUES (1)"}, {SQL: "INSERT INTO notes VALUES (1)"}}
	if _, err := store.ExecSQLite(ctx, req); err == nil {
		t.Fatal("duplicate batch committed")
	}
	rows, err := store.QuerySQLite(ctx, storage.SQLiteQueryRequest{PluginInstanceID: req.PluginInstanceID, ResourceScope: req.ResourceScope, StoreID: req.StoreID, SQL: "SELECT id FROM notes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 0 {
		t.Fatal("batch partially committed")
	}
	req.Statements[1].SQL = "INSERT INTO notes VALUES (2)"
	result, err := store.ExecSQLite(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsAffected != 2 {
		t.Fatal(result)
	}
}
