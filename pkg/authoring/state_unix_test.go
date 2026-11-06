//go:build darwin || linux

package authoring

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestAuthorStateLockDoesNotSurviveChildExec(t *testing.T) {
	const helper = "REDEVPLUGIN_TEST_AUTHOR_LOCK_CHILD"
	if os.Getenv(helper) == "1" {
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}

	root := t.TempDir()
	lock, err := lockAuthorState(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if other, err := lockAuthorState(root); err == nil {
		_ = other.Close()
		t.Fatal("concurrent state owner admitted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuthorStateLockDoesNotSurviveChildExec$")
	child.Env = append(os.Environ(), helper+"=1")
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if err := child.Wait(); err != nil {
			t.Errorf("child did not exit cleanly: %v", err)
		}
	})
	if ready, err := bufio.NewReader(output).ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("child did not execute: %q %v", ready, err)
	}

	// The child remains alive until cleanup closes its input. Closing the
	// owning host must release the lock without stopping unrelated children.
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := lockAuthorState(root)
	if err != nil {
		t.Fatalf("executed child retained the host state lock: %v", err)
	}
	_ = reopened.Close()
}
