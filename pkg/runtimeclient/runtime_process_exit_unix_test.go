//go:build darwin || linux

package runtimeclient

import (
	"os/exec"
	"testing"
)

func TestRuntimeProcessSignalExitIsClassifiedWithoutStatusGuessing(t *testing.T) {
	err := exec.Command("sh", "-c", "kill -TERM $$").Run()
	if got := runtimeProcessFailureCodeFromWaitError(err); got != RuntimeProcessSignalled {
		t.Fatalf("signal exit mapped to %q, want %q", got, RuntimeProcessSignalled)
	}
	if got := classifyRuntimeProcessExit(err, runtimeProcessTerminationStop); got != "" {
		t.Fatalf("expected signal exit mapped to %q, want empty", got)
	}
}
