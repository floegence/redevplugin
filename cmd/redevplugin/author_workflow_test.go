package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/registry"
	"github.com/floegence/redevplugin/v3/pkg/runtimetarget"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthorRuntimeSupportsPrivateStorage(t *testing.T) {
	repo := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repo)
	identity := mustInspectCommandRuntimeArtifact(t, runtimePath)
	var archive bytes.Buffer
	if _, err := pluginpkg.BuildFromDir(context.Background(), filepath.Join(repo, "examples/plugins/memos"), &archive, pluginpkg.DefaultReadLimits()); err != nil {
		t.Fatal(err)
	}
	result, err := authorRuntimeCall(context.Background(), authorOptions{
		runtime: runtimePath, sha: identity.BinarySHA256().String(),
		surface: "memos.view", method: "memos.bootstrap",
		params: `{"month":"2026-10","utc_offset_minutes":0}`,
	}, archive.Bytes())
	if err != nil {
		workerError, worker := host.AsValidatedWorkerExecutionError(err)
		t.Fatalf("author storage bootstrap: %v (worker=%t %+v)", err, worker, workerError)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data struct {
			Memos  []any          `json:"memos"`
			Facets map[string]any `json:"facets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Data.Memos == nil || response.Data.Facets == nil {
		t.Fatalf("private SQLite write/read did not complete: %s (%v)", raw, err)
	}
}

func TestAuthorCLIInvokesRealRuntime(t *testing.T) {
	repo := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repo)
	root := t.TempDir()
	project := filepath.Join(root, "source")
	if _, err := createPluginScaffold("dev.example.author", "Author Preview", project); err != nil {
		t.Fatal(err)
	}
	p, err := authorproject.Load(project)
	if err != nil {
		t.Fatal(err)
	}
	p.Config.Build = []string{"node", "-e", "process.exit(0)"}
	p.Config.Test = []string{"node", "-e", "process.exit(0)"}
	config, _ := json.Marshal(p.Config)
	if err := os.WriteFile(filepath.Join(project, authorproject.ConfigFile), config, 0600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(root, "redevplugin")
	build := exec.Command("go", "build", "-o", cli, "./cmd/redevplugin")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	identity := mustInspectCommandRuntimeArtifact(t, runtimePath)
	command := exec.Command(cli, "test", project, "--runtime", runtimePath, "--runtime-sha256", identity.BinarySHA256().String(), "--surface", "dev.example.author.view", "--method", "worker.echo", "--params", `{"message":"author-cli-runtime"}`)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("CLI runtime: %v\n%s", err, output)
	}
}

func TestAuthorBrowserWorkflow(t *testing.T) {
	if os.Getenv("REDEVPLUGIN_RUN_BROWSER_SMOKE") != "1" {
		t.Skip("real browser acceptance runs in the explicit browser gate")
	}
	repo := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repo)
	cli := filepath.Join(t.TempDir(), "redevplugin")
	build := exec.Command("go", "build", "-o", cli, "./cmd/redevplugin")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "scripts/author_workflow_smoke.mjs", cli, runtimePath)
	command.Dir = repo
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("author browser acceptance: %v\n%s", err, output)
	}
}

func TestAuthorRuntimeRequiresIndependentExpectedDigest(t *testing.T) {
	_, err := authorRuntime(context.Background(), t.TempDir(), "/missing/runtime", "")
	if err == nil {
		t.Fatal("runtime without independently supplied identity was accepted")
	}
}

func TestAuthorWatchCoalescesEditsDuringBuild(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	config := authorproject.Config{SchemaVersion: authorproject.SchemaVersion, Output: "dist", Build: []string{"node"}, Test: []string{"node"}, Watch: []string{"src"}}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(root, authorproject.ConfigFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	project, err := authorproject.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	finished := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(finished)
		watchAuthorProject(ctx, project, func() {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}, func(err error) {
			select {
			case failures <- err:
			default:
			}
		})
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first build did not start")
	}
	for _, value := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(root, "src", "app.ts"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
		t.Fatal("overlapping builds")
	case <-time.After(600 * time.Millisecond):
	}
	release <- struct{}{}
	select {
	case <-started:
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("edit during build was lost")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not stop")
	}
}

func TestAuthorBuildFailureRetainsPreview(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fail.mjs"), []byte("process.exit(7)"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &authorproject.Project{Root: root, Config: authorproject.Config{Build: []string{"node", "fail.mjs"}}}
	builds := &authorBuilds{state: authorBuildState{Generation: 4, PluginInstanceID: "existing"}, record: registry.PluginRecord{PluginInstanceID: "existing"}}
	builds.build(context.Background(), p, nil)
	state := builds.snapshot()
	if state.Generation != 4 || state.PluginInstanceID != "existing" || state.Error == "" || state.Building {
		t.Fatalf("failed build damaged active preview: %#v", state)
	}
}

func TestAuthorTestHostOwnsOnlyItsVerifiedRuntime(t *testing.T) {
	repo := cliRepoRoot(t)
	runtimePath := buildExamplesRuntime(t, repo)
	identity := mustInspectCommandRuntimeArtifact(t, runtimePath)
	ctx := context.Background()
	newModule := func() *host.RuntimeModule {
		t.Helper()
		module, err := newCommandRuntimeModule(ctx, runtimePath, t.TempDir(), identity, 15*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return module
	}
	module := newModule()
	first, err := testhost.Open(ctx, testhost.Options{Runtime: module, Actions: []host.ManagementAction{host.ManagementActionStartRuntime, host.ManagementActionGetRuntimeHealth}})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	target, err := runtimetarget.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Host().StartRuntime(first.Context(ctx), host.StartRuntimeRequest{Target: target}); err != nil {
		t.Fatal(err)
	}
	if second, err := testhost.Open(ctx, testhost.Options{Runtime: module}); err == nil {
		_ = second.Close()
		t.Fatal("consumed module admitted twice")
	}
	health, err := first.Host().RuntimeHealth(first.Context(ctx))
	if err != nil || !health.Ready {
		t.Fatalf("failed construction stopped another Host runtime: %+v %v", health, err)
	}
	rejected := newModule()
	if opened, err := testhost.Open(ctx, testhost.Options{Runtime: rejected, Actions: []host.ManagementAction{"unknown.action"}}); err == nil {
		_ = opened.Close()
		t.Fatal("invalid actions admitted")
	}
	result, err := rejected.Close(ctx)
	if err != nil || result.Disposition != host.RuntimeModuleAlreadyClosed || result.Outcome != host.MutationOutcomeNotCommitted {
		t.Fatalf("failure leaked runtime ownership: %+v %v", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Host().RuntimeHealth(first.Context(ctx)); !errors.Is(err, host.ErrActionDenied) {
		t.Fatalf("closed runtime query = %v", err)
	}
}
