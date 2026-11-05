package authoring

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestWorkspaceArtifactsSurviveRestartAndRejectTampering(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "authors")
	owner := Owner{User: "user", Environment: "environment"}
	store, err := OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	w, err := store.Create(ctx, owner, "draft-1")
	if err != nil {
		t.Fatal(err)
	}
	same, err := store.Create(ctx, owner, "draft-1")
	if err != nil || same.ID != w.ID {
		t.Fatal("create not idempotent", err)
	}
	if _, err = store.Get(ctx, Owner{User: "other", Environment: owner.Environment}, w.ID); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatal("foreign workspace readable", err)
	}
	if _, err = store.Initialize(ctx, owner, w.ID, "dev.example.created", "Created", "web"); err != nil {
		t.Fatal(err)
	}
	a, err := store.Capture(ctx, owner, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(w.SourceDirectory, "ui/src/app.ts"), []byte("modified source"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.ReadArtifact(ctx, owner, w.ID, a.ID); err != nil {
		t.Fatal("immutable artifact invalidated by source edit", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, raw, err := store.ReadArtifact(ctx, owner, w.ID, a.ID)
	if err != nil || len(raw) == 0 || got.PackageSHA256 != a.PackageSHA256 {
		t.Fatal("artifact not recovered", err)
	}
	path := filepath.Join(root, "projects", w.ID, "artifacts", a.ID+".redevplugin")
	if err = os.WriteFile(path, []byte("tamper"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.ReadArtifact(ctx, owner, w.ID, a.ID); err == nil {
		t.Fatal("tampered bytes admitted")
	}
	if err = store.Remove(ctx, owner, w.ID); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove(ctx, owner, w.ID); err != nil {
		t.Fatal("delete not idempotent", err)
	}
	if _, err = store.Create(ctx, owner, "draft-1"); !errors.Is(err, ErrWorkspaceConflict) {
		t.Fatal("deleted workspace resurrected", err)
	}
	if _, err = os.Stat(w.SourceDirectory); !os.IsNotExist(err) {
		t.Fatal("managed source retained", err)
	}
}

func TestWorkspaceRejectsUnknownAndFutureStateWithoutMutation(t *testing.T) {
	for _, mode := range []string{"unknown", "future", "drift"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			root := filepath.Join(t.TempDir(), "authors")
			if mode == "unknown" {
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "author.sqlite"), []byte("not a database"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				s, err := OpenWorkspaceStore(ctx, root)
				if err != nil {
					t.Fatal(err)
				}
				statement := "UPDATE author_schema SET version=99"
				if mode == "drift" {
					statement = "ALTER TABLE workspaces ADD COLUMN unknown TEXT"
				}
				if _, err = s.db.ExecContext(ctx, statement); err != nil {
					t.Fatal(err)
				}
				s.Close()
			}
			before, err := os.ReadFile(filepath.Join(root, "author.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			if store, err := OpenWorkspaceStore(ctx, root); err == nil {
				store.Close()
				t.Fatal("unknown durable state accepted")
			}
			after, err := os.ReadFile(filepath.Join(root, "author.sqlite"))
			if err != nil || string(before) != string(after) {
				t.Fatal("rejected bytes changed", err)
			}
		})
	}
}
func TestWorkspaceCannotFollowManagedSymlinkOutsideRoot(t *testing.T) {
	ctx := context.Background()
	s, err := OpenWorkspaceStore(ctx, filepath.Join(t.TempDir(), "authors"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := Owner{User: "user", Environment: "env"}
	w, err := s.Create(ctx, owner, "create")
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep")
	if err = os.WriteFile(sentinel, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(w.SourceDirectory); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, w.SourceDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Initialize(ctx, owner, w.ID, "dev.example.symlink", "Symlink", "web"); err == nil {
		t.Fatal("symlink initialized")
	}
	if err = s.Remove(ctx, owner, w.ID); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(sentinel); err != nil || string(raw) != "retain" {
		t.Fatal("external files changed", err)
	}
}
func TestWorkspaceRecoversDeletionAndStagedInitialization(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "authors")
	s, err := OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	owner := Owner{User: "user", Environment: "env"}
	w, err := s.Create(ctx, owner, "delete")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE workspaces SET deleting=1 WHERE id=?", w.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, owner, w.ID); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatal("deleting source became available", err)
	}
	if err = s.Remove(ctx, owner, w.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	staged := filepath.Join(t.TempDir(), "authors")
	s, err = OpenWorkspaceStore(ctx, staged)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err = os.Rename(filepath.Join(staged, "author.sqlite"), filepath.Join(staged, ".author-initialize.sqlite")); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWorkspaceStore(ctx, staged)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestWorkspaceCanonicalFixtures(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../spec/plugin/author-workspace.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../spec/plugin/author-workspace-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]any
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for name, value := range fixtures {
		if err = schema.Validate(value); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	ctx := context.Background()
	s, err := OpenWorkspaceStore(ctx, filepath.Join(t.TempDir(), "authors"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := Owner{User: "user", Environment: "env"}
	w, err := s.Create(ctx, owner, "contract")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Initialize(ctx, owner, w.ID, "dev.example.contract", "Contract", "web"); err != nil {
		t.Fatal(err)
	}
	artifact, err := s.Capture(ctx, owner, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{w, artifact} {
		encoded, _ := json.Marshal(v)
		var value any
		if err = json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		if err = schema.Validate(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkspaceInitializationRecoversEveryPersistedStage(t *testing.T) {
	for _, stage := range []string{"building", "prepared", "renamed"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			root := filepath.Join(t.TempDir(), "authors")
			s, err := OpenWorkspaceStore(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			owner := Owner{User: "user", Environment: "environment"}
			w, err := s.Create(ctx, owner, "initialize")
			if err != nil {
				t.Fatal(err)
			}
			dbStage := stage
			if stage == "renamed" {
				dbStage = "prepared"
			}
			if _, err = s.db.Exec("INSERT INTO initializations VALUES(?,?,?,?,?)", w.ID, "dev.example.initialize", "Initialize", "web", dbStage); err != nil {
				t.Fatal(err)
			}
			staging := filepath.Join(root, "projects", w.ID, "initializing")
			if stage == "building" {
				if err = os.Mkdir(staging, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(staging, "partial"), []byte("interrupted"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = Init("dev.example.initialize", "Initialize", staging, "web"); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(w.SourceDirectory); err != nil {
					t.Fatal(err)
				}
				if stage == "renamed" {
					if err = os.Rename(staging, w.SourceDirectory); err != nil {
						t.Fatal(err)
					}
				}
			}
			s.Close()
			s, err = OpenWorkspaceStore(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.Get(ctx, owner, w.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Capture(ctx, owner, w.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Initialize(ctx, owner, w.ID, "dev.example.initialize", "Initialize", "web"); err != nil {
				t.Fatal("idempotent init", err)
			}
			if _, err = s.Initialize(ctx, owner, w.ID, "dev.example.foreign", "Foreign", "web"); !errors.Is(err, ErrWorkspaceConflict) {
				t.Fatal("rebound initialization", err)
			}
		})
	}
}

func TestWorkspaceBuildFailureSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "authors")
	owner := Owner{"user", "env"}
	s, err := OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Create(ctx, owner, "failed-build")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Initialize(ctx, owner, w.ID, "dev.example.failed", "Failed", "web"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(w.SourceDirectory, "manifest.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Build(ctx, owner, w.ID, authorproject.PipelineOptions{}); err == nil {
		t.Fatal("invalid manifest accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	report, err := s.BuildReport(ctx, owner, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.Status != "failed" || report.Error == "" || len(report.Stages) == 0 {
		t.Fatalf("lost report: %+v", report)
	}
	if _, err = s.BuildReport(ctx, Owner{"other", "env"}, w.ID); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatal(err)
	}
}

func TestWorkspaceRecoversInterruptedBuildReport(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "authors")
	owner := Owner{"user", "env"}
	s, err := OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Create(ctx, owner, "interrupted")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.saveBuildReport(ctx, BuildReport{WorkspaceID: w.ID, Status: "running", StartedAt: time.Now(), Stages: []authorproject.Stage{}, Commands: []authorproject.CommandResult{}}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWorkspaceStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	report, err := s.BuildReport(ctx, owner, w.ID)
	if err != nil || report == nil || report.Status != "interrupted" {
		t.Fatalf("report: %+v, %v", report, err)
	}
}
