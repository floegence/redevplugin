package host

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/floegence/redevplugin/pkg/runtimeclient"
)

func TestRuntimeLifecycleUsesInjectedSupervisor(t *testing.T) {
	supervisor := &recordingRuntimeSupervisor{
		health: runtimeclient.Health{RuntimeInstanceID: "runtime_1", RuntimeGenerationID: "runtime_gen_1", Ready: true},
	}
	h, _, audits := newTestHostWithOptions(t, testHostOptions{
		developerMode:     true,
		localGenerated:    true,
		runtimeSupervisor: supervisor,
	})

	health, err := h.StartRuntime(context.Background(), StartRuntimeRequest{Target: RuntimeTarget{OS: "test-os", Arch: "test-arch"}})
	if err != nil {
		t.Fatalf("StartRuntime() error = %v", err)
	}
	if health.RuntimeInstanceID != "runtime_1" || supervisor.startedTarget.OS != "test-os" || supervisor.startedTarget.Arch != "test-arch" {
		t.Fatalf("runtime start mismatch: health=%#v supervisor=%#v", health, supervisor)
	}
	if !audits.hasEvent("plugin.runtime.started") {
		t.Fatalf("missing runtime started audit: %#v", audits.events)
	}

	if err := h.StopRuntime(context.Background()); err != nil {
		t.Fatalf("StopRuntime() error = %v", err)
	}
	if supervisor.stopCalls != 1 || !audits.hasEvent("plugin.runtime.stopped") {
		t.Fatalf("runtime stop mismatch: stopCalls=%d audits=%#v", supervisor.stopCalls, audits.events)
	}
}

func TestStartRuntimeRequiresResolverWhenSupervisorMissing(t *testing.T) {
	h, _, _ := newTestHostWithOptions(t, testHostOptions{developerMode: true, localGenerated: true})
	if _, err := h.StartRuntime(context.Background(), StartRuntimeRequest{}); err == nil {
		t.Fatal("StartRuntime() expected resolver error")
	}
}

func TestStartRuntimeUsesArtifactResolver(t *testing.T) {
	resolver := &recordingRuntimeArtifactResolver{path: filepath.Join(t.TempDir(), "missing-runtime")}
	h, _, _ := newTestHostWithOptions(t, testHostOptions{
		developerMode:           true,
		localGenerated:          true,
		runtimeArtifactResolver: resolver,
	})
	health, err := h.RuntimeHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatalf("RuntimeHealth() should be not ready before start: %#v", health)
	}
	if _, err := h.StartRuntime(context.Background(), StartRuntimeRequest{}); err == nil {
		t.Fatal("StartRuntime() expected missing runtime binary error")
	}
	if resolver.calls != 1 || resolver.target.OS == "" || resolver.target.Arch == "" {
		t.Fatalf("resolver call mismatch: %#v", resolver)
	}
}
