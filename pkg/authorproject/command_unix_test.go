//go:build !windows

package authorproject

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunCancellationTerminatesOwnedChildProcess(t *testing.T) {
	root := t.TempDir()
	child := "import {writeFileSync} from 'node:fs'; setInterval(()=>writeFileSync('heartbeat',String(Date.now())),20);"
	if err := os.WriteFile(filepath.Join(root, "child.mjs"), []byte(child), 0600); err != nil {
		t.Fatal(err)
	}
	parent := "import {spawn} from 'node:child_process'; import {writeFileSync} from 'node:fs'; const child=spawn(process.execPath,['child.mjs']); writeFileSync('child.pid',String(child.pid)); setInterval(()=>{},1000);"
	if err := os.WriteFile(filepath.Join(root, "parent.mjs"), []byte(parent), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := Project{Root: root}
	done := make(chan error, 1)
	go func() { _, err := p.Run(ctx, []string{"node", "parent.mjs"}); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "heartbeat")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, err := os.ReadFile(filepath.Join(root, "child.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGKILL) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled command succeeded")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("command cancellation did not finish")
	}
	deadline = time.Now().Add(4 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned child survived cancellation")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
