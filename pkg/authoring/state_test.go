package authoring

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/connectivity"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/secrets"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func authorTestProject(t *testing.T) *authorproject.Project {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	if _, err := Init("dev.example.state", "State", root, "web"); err != nil {
		t.Fatal(err)
	}
	p, err := authorproject.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	p.Config.Typecheck = nil
	p.Config.Build = []string{"node", "-e", "process.exit(0)"}
	p.Config.Test = []string{"node", "-e", "process.exit(0)"}
	raw, _ := json.Marshal(p.Config)
	if err := os.WriteFile(filepath.Join(root, authorproject.ConfigFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	p, err = authorproject.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestAuthorStateRetainsOwnerAndRotatesSession(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("persistent state platform")
	}
	p := authorTestProject(t)
	root := filepath.Join(t.TempDir(), "state")
	first, err := OpenState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	original := first.record
	if second, err := OpenState(p, root); err == nil {
		second.Close()
		t.Fatal("concurrent owner admitted")
	}
	fresh := first.Renew()
	if fresh.OwnerUserHash != original.User || fresh.OwnerEnvHash != original.Environment || fresh.OwnerSessionHash == original.Session || fresh.SessionChannelIDHash == original.Channel {
		t.Fatal("session renewal changed owner or retained authority")
	}
	if err := first.Save(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.record.session() != fresh {
		t.Fatal("saved generation was lost")
	}
}
func TestAuthorStateRejectsForeignAndUnknownStateWithoutMutation(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("persistent state platform")
	}
	p := authorTestProject(t)
	root := t.TempDir()
	path := filepath.Join(root, "unknown")
	if err := os.WriteFile(path, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(p, root); err == nil {
		t.Fatal("unknown state admitted")
	}
	entries, _ := os.ReadDir(root)
	raw, _ := os.ReadFile(path)
	if len(entries) != 1 || string(raw) != "retain" {
		t.Fatal("unknown state changed")
	}
	if _, err := OpenState(p, filepath.Join(p.Root, "state")); err == nil {
		t.Fatal("source state admitted")
	}
	root = filepath.Join(t.TempDir(), "known")
	state, err := OpenState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
	before, _ := os.ReadFile(filepath.Join(root, "author-state.json"))
	other := authorTestProject(t)
	if _, err := OpenState(other, root); err == nil {
		t.Fatal("foreign project admitted")
	}
	after, _ := os.ReadFile(filepath.Join(root, "author-state.json"))
	if string(before) != string(after) {
		t.Fatal("foreign state changed")
	}
}
func TestAuthorCandidateAppliesOnceAndRejectsStaleSource(t *testing.T) {
	p := authorTestProject(t)
	h, err := testhost.Open(context.Background(), authorHostOptions(t.TempDir(), "http://localhost:12345", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx := h.Context(context.Background())
	s := &Preview{state: PreviewState{Mode: "web", Manual: true}}
	s.Build(ctx, p, h.Host())
	initial := s.Snapshot()
	if initial.Error != "" || initial.Generation != 1 {
		t.Fatalf("initial build: %+v", initial)
	}
	s.Build(ctx, p, h.Host())
	if !s.Snapshot().Candidate || s.Snapshot().Generation != 1 {
		t.Fatal("manual update replaced preview")
	}
	if err := s.Apply(ctx, p, h.Host()); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, p, h.Host()); err == nil {
		t.Fatal("candidate replay admitted")
	}
	s.Build(ctx, p, h.Host())
	if err := os.WriteFile(filepath.Join(p.Root, "ui/src/application.ts"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, p, h.Host()); err == nil {
		t.Fatal("stale candidate admitted")
	}
	if s.Snapshot().Generation != 2 || s.Snapshot().RestartRequired {
		t.Fatal("stale source damaged active preview")
	}
}
func TestAuthorSessionCleanupIsRepeatableAcrossRestart(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("persistent state platform")
	}
	p := authorTestProject(t)
	state, err := OpenState(p, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	options := authorHostOptions(state.root, "http://localhost:12345", nil)
	session := state.record.session()
	options.Session = &session
	h, err := testhost.Open(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := CloseSession(context.Background(), h.Host(), session); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := state.Renew()
	options.Session = &fresh
	h, err = testhost.Open(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := CloseSession(context.Background(), h.Host(), session); err != nil {
		t.Fatal(err)
	}
	if err := CloseSession(context.Background(), h.Host(), fresh); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorStateRecoversCompleteStagedMarker(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("persistent state platform")
	}
	p := authorTestProject(t)
	root := filepath.Join(t.TempDir(), "state")
	state, err := OpenState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	record := state.record
	state.Close()
	if err := os.Rename(filepath.Join(root, "author-state.json"), filepath.Join(root, ".author-state-interrupted")); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.record != record {
		t.Fatal("staged identity changed")
	}
}
func TestAuthorResetCreatesFreshInstance(t *testing.T) {
	p := authorTestProject(t)
	h, err := testhost.Open(context.Background(), authorHostOptions(t.TempDir(), "http://localhost:12345", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx := h.Context(context.Background())
	builds := &Preview{state: PreviewState{Mode: "web"}}
	builds.Build(ctx, p, h.Host())
	before := builds.Snapshot()
	if before.Error != "" {
		t.Fatal(before.Error)
	}
	if err := builds.Reset(ctx, h.Host(), before.Generation+1); err == nil {
		t.Fatal("stale reset review accepted")
	}
	if err := builds.Reset(ctx, h.Host(), before.Generation); err != nil {
		t.Fatal(err)
	}
	builds.Build(ctx, p, h.Host())
	after := builds.Snapshot()
	if after.Error != "" || after.PluginInstanceID == before.PluginInstanceID || after.Generation != before.Generation+1 {
		t.Fatalf("reset: %+v", after)
	}
}
func TestAuthorPipelineStopsAfterTypeFailureAndDetectsSourceMutation(t *testing.T) {
	for _, stage := range []string{"typecheck", "source-consistency"} {
		t.Run(stage, func(t *testing.T) {
			p := authorTestProject(t)
			if stage == "typecheck" {
				p.Config.Typecheck = []string{"node", "-e", "process.exit(9)"}
			} else {
				p.Config.Build = []string{"node", "-e", "require('fs').appendFileSync('ui/src/app.ts','changed')"}
			}
			raw, _ := json.Marshal(p.Config)
			if err := os.WriteFile(filepath.Join(p.Root, authorproject.ConfigFile), raw, 0600); err != nil {
				t.Fatal(err)
			}
			p, err := authorproject.Load(p.Root)
			if err != nil {
				t.Fatal(err)
			}
			result, err := p.Build(context.Background(), authorproject.PipelineOptions{Test: true})
			if err == nil || result.Stages[len(result.Stages)-1].Name != stage || len(result.Bytes) != 0 {
				t.Fatalf("unexpected result: %+v %v", result.Stages, err)
			}
		})
	}
}

func TestAuthorStateCanonicalSchemaAndStrictParser(t *testing.T) {
	p := authorTestProject(t)
	record := authorStateRecord{Schema: "redevplugin.author-state.v1", Project: p.Root, User: "user", Environment: "environment", Session: "session", Channel: "channel"}
	raw, _ := json.Marshal(record)
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../spec/plugin/author-development.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatal(err)
	}
	if err := decodeAuthorState(raw, p.Root, new(authorStateRecord)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append([]byte(`{"schema":"redevplugin.author-state.v1",`), raw[1:]...), []byte(`{"Schema":"redevplugin.author-state.v1"}`), append(raw, []byte(`{}`)...)} {
		if decodeAuthorState(bad, p.Root, new(authorStateRecord)) == nil {
			t.Fatal("ambiguous marker admitted")
		}
	}
}

func authorHostOptions(root, origin string, _ *host.RuntimeModule) testhost.Options {
	return testhost.Options{Secrets: &host.SecretsModule{Store: secrets.NewMemoryStore()}, Connectivity: &host.ConnectivityModule{Broker: connectivity.NewMemoryBroker(), NetworkExecutor: connectivity.NewExecutor(connectivity.ExecutorOptions{})}, StateRoot: root, ParentOrigin: origin, AllowLocalPackages: true, Actions: []host.ManagementAction{host.ManagementActionListPlugins, host.ManagementActionImportLocalPackage, host.ManagementActionUpdateLocalPackage, host.ManagementActionUninstallPlugin}}
}

func TestAuthorBuildFailureRetainsPreview(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fail.mjs"), []byte("process.exit(7)"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &authorproject.Project{Root: root, Config: authorproject.Config{Build: []string{"node", "fail.mjs"}}}
	builds := &Preview{state: PreviewState{Generation: 4, PluginInstanceID: "existing"}, record: registry.PluginRecord{PluginInstanceID: "existing"}}
	builds.Build(context.Background(), p, nil)
	state := builds.Snapshot()
	if state.Generation != 4 || state.PluginInstanceID != "existing" || state.Error == "" || state.Building {
		t.Fatalf("failed build damaged active preview: %#v", state)
	}
}
