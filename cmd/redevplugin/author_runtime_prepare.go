package main

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/version"
)

//go:embed author_assets/runtime-prepare.mjs
var authorRuntimePrepare []byte

func runAuthorRuntimePrepare(ctx context.Context, args []string) error {
	if len(args) != 2 || args[0] != "prepare" {
		return errors.New("usage: redevplugin runtime prepare <new-directory>")
	}
	for _, tool := range []string{"node", "gh", "rustup", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			return err
		}
	}
	root, err := os.MkdirTemp("", "redevplugin-runtime-command-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	path := filepath.Join(root, "prepare.mjs")
	if err := os.WriteFile(path, authorRuntimePrepare, 0600); err != nil {
		return err
	}
	output, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "node", path, version.CurrentPlatformVersion(), output)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.WaitDelay = 2 * time.Second
	configureAuthorProcess(command)
	defer finishAuthorProcess(command)
	return command.Run()
}
