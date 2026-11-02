package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/floegence/redevplugin/v3/pkg/authorapi"
)

func generateAuthorAPI(input, output string, check bool) error {
	inputPath, err := filepath.EvalSymlinks(input)
	if err != nil {
		return err
	}
	inputPath, err = filepath.Abs(inputPath)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return err
	}
	files, err := authorapi.Generate(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", input, err)
	}
	if !check {
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			return err
		}
	}
	resolved, err := filepath.EvalSymlinks(outputPath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generated output directory must not be a symlink")
	}
	output = resolved
	if filepath.Join(resolved, "manifest.json") == inputPath {
		return fmt.Errorf("generated output must not overwrite the source manifest")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(output, name)
		info, err := os.Lstat(path)
		if err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("%s: generated output must be a regular file", path)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, name := range names {
		path := filepath.Join(output, name)
		if check {
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(current, files[name]) {
				return fmt.Errorf("%s: generated output is stale; run redevplugin generate", path)
			}
		} else {
			// Rename replaces a directory entry rather than following a raced symlink.
			staged, err := os.CreateTemp(output, ".redevplugin-generate-*")
			if err != nil {
				return err
			}
			stagedName := staged.Name()
			defer os.Remove(stagedName)
			if _, err = staged.Write(files[name]); err == nil {
				err = staged.Chmod(0644)
			}
			closeErr := staged.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if err := os.Rename(stagedName, path); err != nil {
				return err
			}
		}
	}
	return writeJSON(map[string]any{"ok": true, "checked": check, "files": names})
}
