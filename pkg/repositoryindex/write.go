package repositoryindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"io"
	"os"
	"path/filepath"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

// Upsert validates the complete repository before atomically changing its index.
// Existing entries require explicit replacement unless the declaration is identical.
func Upsert(root, host, project, manifestName string, release Release, replace bool) (bool, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return false, err
	}
	source, err := repositoryPath(absolute, project, manifestName)
	if err != nil {
		return false, fmt.Errorf("project manifest: %w", err)
	}
	file, err := os.Open(source)
	if err != nil {
		return false, err
	}
	rawSource, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	decoded, _, decodeErr := manifest.CompileSource(rawSource, pluginidentity.Identity{})
	decodeErr = errors.Join(readErr, decodeErr)
	closeErr := file.Close()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return false, err
	}
	entry := Plugin{Slug: decoded.PluginID(), Path: project, Manifest: manifestName, Release: &release}
	indexPath := filepath.Join(absolute, IndexPath)
	directory := filepath.Dir(indexPath)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return false, err
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return false, err
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("index directory must not be a symlink")
	}
	lock, err := lockIndex(directory)
	if err != nil {
		return false, fmt.Errorf("acquire index write lock: %w", err)
	}
	defer lock.Close()
	index := Index{SchemaVersion: SchemaVersion}
	info, err := os.Lstat(indexPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false, errors.New("index must be a regular file")
		}
		repo, err := Load(absolute)
		if err != nil {
			return false, err
		}
		index = repo.Index
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	foundTarget, foundEntry := false, false
	for ti := range index.Targets {
		target := &index.Targets[ti]
		if target.Host != host || target.Ecosystem != "redevplugin" {
			continue
		}
		foundTarget = true
		for pi := range target.Plugins {
			old := target.Plugins[pi]
			if old.Slug != entry.Slug && (!replace || old.Path != entry.Path || old.Manifest != entry.Manifest) {
				continue
			}
			foundEntry = true
			if old.Slug == entry.Slug && old.Path == entry.Path && old.Manifest == entry.Manifest && old.Release != nil && *old.Release == release {
				_, err := ValidateRepository(absolute)
				return false, err
			}
			if !replace {
				return false, fmt.Errorf("plugin %q already has a different declaration; use --replace to update it", entry.Slug)
			}
			target.Plugins[pi] = entry
		}
		if !foundEntry {
			target.Plugins = append(target.Plugins, entry)
		}
	}
	if !foundTarget {
		index.Targets = append(index.Targets, Target{Ecosystem: "redevplugin", Host: host, Plugins: []Plugin{entry}})
	}
	if err := Validate(index); err != nil {
		return false, err
	}
	for _, target := range index.Targets {
		for _, item := range target.Plugins {
			if err := validatePluginManifest(absolute, item); err != nil {
				return false, err
			}
		}
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return false, err
	}
	raw = append(raw, '\n')
	if len(raw) > MaxBytes {
		return false, errors.New("repository index exceeds size limit")
	}
	temporary, err := os.CreateTemp(directory, ".index-*.json")
	if err != nil {
		return false, err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Chmod(0644); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporary.Name(), indexPath); err != nil {
		return false, err
	}
	return true, syncIndexDirectory(directory)
}
