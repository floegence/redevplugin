package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
)

func checkEnclosingRepositoryIndex(projectRoot, pluginID string) error {
	project, err := filepath.Abs(projectRoot)
	if err != nil {
		return err
	}
	project, err = filepath.EvalSymlinks(project)
	if err != nil {
		return err
	}
	for dir := project; ; dir = filepath.Dir(dir) {
		_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(repositoryindex.IndexPath)))
		if err == nil {
			repo, err := repositoryindex.ValidateRepository(dir)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(repo.Root, project)
			if err != nil {
				return err
			}
			for _, entry := range repo.Entries {
				if entry.Plugin.PluginID == pluginID && entry.Plugin.Path == filepath.ToSlash(rel) {
					return nil
				}
			}
			return fmt.Errorf("project %q with plugin_id %q is not listed", filepath.ToSlash(rel), pluginID)
		}
		if !os.IsNotExist(err) {
			return err
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}
