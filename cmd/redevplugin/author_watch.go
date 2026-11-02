package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/fsnotify/fsnotify"
)

// Events schedule bounded content verification. Hashes, never timestamps or
// filesystem notifications, remain the authority for candidate admission.
func watchAuthorProject(ctx context.Context, p *authorproject.Project, build func(), onError func(error)) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		onError(err)
		return
	}
	defer watcher.Close()
	inputs := append([]string{authorproject.ConfigFile, "manifest.json"}, p.Config.Watch...)
	relevant := func(path string) bool {
		relative, err := filepath.Rel(p.Root, path)
		if err != nil || !filepath.IsLocal(relative) {
			return false
		}
		relative = filepath.ToSlash(relative)
		for _, part := range strings.Split(relative, "/") {
			if part == "node_modules" || part == "target" || part == ".git" {
				return false
			}
		}
		for _, input := range inputs {
			if relative == input || strings.HasPrefix(relative, input+"/") || strings.HasPrefix(input, relative+"/") {
				return true
			}
		}
		return false
	}
	refresh := func() error {
		existing := map[string]bool{}
		for _, path := range watcher.WatchList() {
			existing[path] = true
		}
		add := func(path string) error {
			if existing[path] {
				return nil
			}
			if err := watcher.Add(path); err != nil {
				return err
			}
			existing[path] = true
			return nil
		}
		if err := add(p.Root); err != nil {
			return err
		}
		for _, input := range inputs {
			path := filepath.Join(p.Root, input)
			// Watch existing parents too, so newly created nested inputs are detected.
			for parent := filepath.Dir(path); parent != p.Root && withinAuthorPath(p.Root, parent); parent = filepath.Dir(parent) {
				if info, err := os.Lstat(parent); err == nil && info.IsDir() {
					if err := add(parent); err != nil {
						return err
					}
				}
			}
			err := filepath.WalkDir(path, func(path string, entry fs.DirEntry, err error) error {
				if os.IsNotExist(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if !relevant(path) {
					if entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if entry.IsDir() {
					return add(path)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	}
	last, err := p.Snapshot(ctx)
	if err != nil {
		onError(err)
		return
	}
	if err := refresh(); err != nil {
		onError(err)
		return
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	fallback := time.NewTicker(10 * time.Second)
	defer fallback.Stop()
	done := make(chan struct{}, 1)
	running, pending, failed := false, false, false
	start := func() { running = true; pending = false; go func() { build(); done <- struct{}{} }() }
	scan := func() {
		digest, err := p.Snapshot(ctx)
		if err != nil {
			failed = true
			onError(err)
			return
		}
		if digest != last || failed {
			pending = true
			last = digest
			failed = false
		}
		if err := refresh(); err != nil {
			onError(err)
		}
	}
	start()
	for {
		select {
		case <-ctx.Done():
			if running {
				<-done
			}
			return
		case <-done:
			running = false
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if relevant(event.Name) {
				timer.Reset(250 * time.Millisecond)
			}
		case failure, ok := <-watcher.Errors:
			if !ok {
				return
			}
			onError(failure)
			timer.Reset(250 * time.Millisecond)
		case <-timer.C:
			scan()
		case <-fallback.C:
			scan()
		}
		if pending && !running {
			start()
		}
	}
}
