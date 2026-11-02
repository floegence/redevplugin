package plugindata

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

func TestFilesNamespaceMigrationCrashRecovery(t *testing.T) {
	if root := os.Getenv("REDEVPLUGIN_MIGRATION_CRASH_ROOT"); root != "" {
		checkpoint, _ := strconv.Atoi(os.Getenv("REDEVPLUGIN_MIGRATION_CRASH_STAGE"))
		db, err := openNamespaceDatabase(context.Background(), root, false)
		if err != nil {
			t.Fatal(err)
		}
		err = migrateFilesNamespaceAtCheckpoint(context.Background(), db, func(stage int) {
			if stage == checkpoint {
				os.Exit(73)
			}
		})
		t.Fatalf("crash checkpoint not reached: %v", err)
	}
	for stage := 1; stage <= 4; stage++ {
		t.Run(strconv.Itoa(stage), func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			db, err := openNamespaceDatabase(ctx, root, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=1;`, namespaceDatabaseApplicationID) + legacyFilesNamespaceSchema + `INSERT INTO file_entries VALUES('draft','.',0,x'6162',2,1); UPDATE namespace_usage SET usage_bytes=2,usage_files=1;`)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestFilesNamespaceMigrationCrashRecovery$")
			child.Env = append(os.Environ(), "REDEVPLUGIN_MIGRATION_CRASH_ROOT="+root, "REDEVPLUGIN_MIGRATION_CRASH_STAGE="+strconv.Itoa(stage))
			if output, err := child.CombinedOutput(); err == nil || child.ProcessState.ExitCode() != 73 {
				t.Fatalf("child: %v %s", err, output)
			}
			db, err = openNamespaceDatabase(ctx, root, false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			for range 2 {
				if err = migrateFilesNamespace(ctx, db); err != nil {
					t.Fatal(err)
				}
			}
			var data []byte
			var version int
			if err = db.QueryRow(`SELECT content FROM file_entries WHERE path='draft'`).Scan(&data); err != nil || string(data) != "ab" {
				t.Fatalf("retained content: %q %v", data, err)
			}
			if err = db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 2 {
				t.Fatalf("version %d %v", version, err)
			}
		})
	}
}
