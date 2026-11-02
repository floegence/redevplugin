package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func authorTestProject(t *testing.T) *authorproject.Project {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	if _, err := createPluginTemplate("dev.example.state", "State", root, "web"); err != nil {
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
	first, err := openAuthorState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	original := first.record
	if second, err := openAuthorState(p, root); err == nil {
		second.close()
		t.Fatal("concurrent owner admitted")
	}
	fresh := first.renew()
	if fresh.OwnerUserHash != original.User || fresh.OwnerEnvHash != original.Environment || fresh.OwnerSessionHash == original.Session || fresh.SessionChannelIDHash == original.Channel {
		t.Fatal("session renewal changed owner or retained authority")
	}
	if err := first.save(); err != nil {
		t.Fatal(err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	second, err := openAuthorState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
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
	if _, err := openAuthorState(p, root); err == nil {
		t.Fatal("unknown state admitted")
	}
	entries, _ := os.ReadDir(root)
	raw, _ := os.ReadFile(path)
	if len(entries) != 1 || string(raw) != "retain" {
		t.Fatal("unknown state changed")
	}
	if _, err := openAuthorState(p, filepath.Join(p.Root, "state")); err == nil {
		t.Fatal("source state admitted")
	}
	root = filepath.Join(t.TempDir(), "known")
	state, err := openAuthorState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	state.close()
	before, _ := os.ReadFile(filepath.Join(root, "author-state.json"))
	other := authorTestProject(t)
	if _, err := openAuthorState(other, root); err == nil {
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
	s := &authorBuilds{state: authorBuildState{Mode: "web", Manual: true}}
	s.build(ctx, p, h.Host())
	initial := s.snapshot()
	if initial.Error != "" || initial.Generation != 1 {
		t.Fatalf("initial build: %+v", initial)
	}
	s.build(ctx, p, h.Host())
	if !s.snapshot().Candidate || s.snapshot().Generation != 1 {
		t.Fatal("manual update replaced preview")
	}
	if err := s.apply(ctx, p, h.Host()); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(ctx, p, h.Host()); err == nil {
		t.Fatal("candidate replay admitted")
	}
	s.build(ctx, p, h.Host())
	if err := os.WriteFile(filepath.Join(p.Root, "ui/src/application.ts"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(ctx, p, h.Host()); err == nil {
		t.Fatal("stale candidate admitted")
	}
	if s.snapshot().Generation != 2 || s.snapshot().RestartRequired {
		t.Fatal("stale source damaged active preview")
	}
}
func TestAuthorSessionCleanupIsRepeatableAcrossRestart(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("persistent state platform")
	}
	p := authorTestProject(t)
	state, err := openAuthorState(p, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.close()
	options := authorHostOptions(state.root, "http://localhost:12345", nil)
	session := state.record.session()
	options.Session = &session
	h, err := testhost.Open(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeAuthorSession(context.Background(), h.Host(), session); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	fresh := state.renew()
	options.Session = &fresh
	h, err = testhost.Open(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := closeAuthorSession(context.Background(), h.Host(), session); err != nil {
		t.Fatal(err)
	}
	if err := closeAuthorSession(context.Background(), h.Host(), fresh); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorStateRecoversCompleteStagedMarker(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("persistent state platform")
	}
	p := authorTestProject(t)
	root := filepath.Join(t.TempDir(), "state")
	state, err := openAuthorState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	record := state.record
	state.close()
	if err := os.Rename(filepath.Join(root, "author-state.json"), filepath.Join(root, ".author-state-interrupted")); err != nil {
		t.Fatal(err)
	}
	reopened, err := openAuthorState(p, root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
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
	builds := &authorBuilds{state: authorBuildState{Mode: "web"}}
	builds.build(ctx, p, h.Host())
	before := builds.snapshot()
	if before.Error != "" {
		t.Fatal(before.Error)
	}
	if err := builds.reset(ctx, h.Host(), before.Generation+1); err == nil {
		t.Fatal("stale reset review accepted")
	}
	if err := builds.reset(ctx, h.Host(), before.Generation); err != nil {
		t.Fatal(err)
	}
	builds.build(ctx, p, h.Host())
	after := builds.snapshot()
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
