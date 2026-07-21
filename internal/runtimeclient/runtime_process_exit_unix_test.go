//go:build darwin || linux

package runtimeclient

import (
	"os/exec"
	"testing"

	"github.com/floegence/redevplugin/pkg/observability"
)

func TestRuntimeProcessSignalExitIsClassifiedWithoutStatusGuessing(t *testing.T) {
	err := exec.Command("sh", "-c", "kill -TERM $$").Run()
	if got := runtimeProcessFailureCodeFromWaitError(err); got != observability.RuntimeProcessSignalled {
		t.Fatalf("signal exit mapped to %q, want %q", got, observability.RuntimeProcessSignalled)
	}
	if got := classifyRuntimeProcessExit(err, runtimeProcessTerminationStop); got != "" {
		t.Fatalf("expected signal exit mapped to %q, want empty", got)
	}
}
