package controlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestOpenFreshV3ControlStoreAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sqlite")
	store, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Generation(); got != 1 {
		t.Fatalf("generation = %d, want 1", got)
	}
	var kind string
	var version int
	if err := store.db.QueryRow(`SELECT kind, version FROM control_schema WHERE id=1`).Scan(&kind, &version); err != nil {
		t.Fatal(err)
	}
	if kind != schemaKind || version != schemaVersion {
		t.Fatalf("schema identity = %q v%d", kind, version)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Generation() != 1 {
		t.Fatalf("reopened generation = %d, want 1", reopened.Generation())
	}
	var namespaceTables int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'plugin_namespace%'`).Scan(&namespaceTables); err != nil {
		t.Fatal(err)
	}
	if namespaceTables != 0 {
		t.Fatalf("plugin namespace leaked into control DB: %d tables", namespaceTables)
	}
}

func TestFreshV3ControlStoreConstrainsEnableStateToCurrentLifecycle(t *testing.T) {
	ctx := pluginDataCatalogContext("env-lifecycle-check", "user-lifecycle-check")
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	record, binding, shape := freshPluginDataCatalogInstall(t, "env-lifecycle-check", "plugini_lifecycle_check")
	if _, err := store.InstallCommit(ctx, record, nil, binding, shape, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE plugin_records SET state='disabled_by_policy' WHERE owner_env_hash=? AND plugin_instance_id=?`, "env-lifecycle-check", record.PluginInstanceID); err == nil {
		t.Fatal("fresh v3 control store accepted a retired enable state")
	}

	var schemaSQL string
	if err := store.db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='plugin_records'`).Scan(&schemaSQL); err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(schemaSQL), " ")
	if !strings.Contains(compact, "CHECK(state IN ('enabled','disabled_by_user'))") {
		t.Fatalf("plugin_records lifecycle constraint is missing: %s", compact)
	}
}

func TestExecutionEventUsesOnePersistentIdentity(t *testing.T) {
	store, err := Open(context.Background(), Config{Path: filepath.Join(t.TempDir(), "control.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateExecution(context.Background(), Execution{ID: "exec-1", PluginInstanceID: "plugin-1", Kind: "subscription", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendEvent(context.Background(), Event{ExecutionID: "exec-1", Sequence: 1, Kind: "data", Payload: map[string]any{"ok": true}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetExecution(context.Background(), "exec-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cursor != 1 || got.ID != "exec-1" {
		t.Fatalf("execution = %#v", got)
	}
	if err := store.AppendEvent(context.Background(), Event{ExecutionID: "exec-1", Sequence: 1, Kind: "data"}); err == nil {
		t.Fatal("duplicate event sequence accepted")
	}
}

func TestOpenRejectsNonCurrentControlStoreWithoutMutation(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "wrong kind", setup: func(t *testing.T, path string) {
			mutateCurrentStore(t, path, `UPDATE control_schema SET kind='redevplugin_control_v2' WHERE id=1`)
		}},
		{name: "future version", setup: func(t *testing.T, path string) {
			mutateCurrentStore(t, path, `UPDATE control_schema SET version=999 WHERE id=1`)
		}},
		{name: "shape drift", setup: func(t *testing.T, path string) { mutateCurrentStore(t, path, `CREATE TABLE shadow_authority(id TEXT)`) }},
		{name: "constraint drift", setup: func(t *testing.T, path string) {
			mutateCurrentStore(t, path, `ALTER TABLE control_metadata RENAME TO old_control_metadata; CREATE TABLE control_metadata(key TEXT, value_json TEXT); DROP TABLE old_control_metadata`)
		}},
		{name: "legacy root", setup: func(t *testing.T, path string) {
			db := openControlTestDB(t, path)
			if _, err := db.Exec(`CREATE TABLE plugin_records(plugin_instance_id TEXT PRIMARY KEY, activation_request_json TEXT NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sqlite")
			if test.name != "legacy root" {
				store, err := Open(context.Background(), Config{Path: path})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			test.setup(t, path)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(context.Background(), Config{Path: path}); !errors.Is(err, ErrIncompatible) {
				if opened != nil {
					_ = opened.Close()
				}
				t.Fatalf("Open() error = %v, want ErrIncompatible", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("rejected control database changed on disk")
			}
		})
	}
}

func TestOpenRequiresExplicitPath(t *testing.T) {
	if _, err := Open(context.Background(), Config{}); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("Open() error = %v, want ErrIncompatible", err)
	}
}

func mutateCurrentStore(t *testing.T, path, statement string) {
	t.Helper()
	db := openControlTestDB(t, path)
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func openControlTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func assertJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("decode got JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode want JSON: %v", err)
	}
	gotJSON, _ := json.Marshal(gotValue)
	wantJSON, _ := json.Marshal(wantValue)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}
