package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/repositoryindex"
)

func runRepositoryIndex(args []string) error {
	if len(args) == 3 && args[0] == "inspect" && args[2] == "--json" {
		args = args[:2]
	}
	if len(args) != 2 || (args[0] != "inspect" && args[0] != "validate") {
		return errors.New("usage: redevplugin repository inspect|validate <repository-root>")
	}
	var repo repositoryindex.Repository
	var err error
	if args[0] == "validate" {
		repo, err = repositoryindex.ValidateRepository(args[1])
	} else {
		repo, err = repositoryindex.Load(args[1])
	}
	if err != nil {
		return err
	}
	type entry struct {
		Ecosystem    string                 `json:"ecosystem"`
		Host         string                 `json:"host"`
		Plugin       repositoryindex.Plugin `json:"plugin"`
		PolicySHA256 string                 `json:"policy_sha256"`
	}
	entries := make([]entry, 0, len(repo.Entries))
	for _, item := range repo.Entries {
		digest, err := repositoryindex.PolicyDigest(item.Target.Host, item.Plugin)
		if err != nil {
			return fmt.Errorf("entry policy: %w", err)
		}
		entries = append(entries, entry{item.Target.Ecosystem, item.Target.Host, item.Plugin, digest})
	}
	return writeJSON(struct {
		OK            bool    `json:"ok"`
		SchemaVersion string  `json:"schema_version"`
		IndexSHA256   string  `json:"index_sha256"`
		RawSHA256     string  `json:"raw_sha256"`
		Entries       []entry `json:"entries"`
	}{true, repositoryindex.SchemaVersion, repo.SHA256, repo.RawSHA256, entries})
}

func scaffoldRepositoryIndex(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: redevplugin scaffold repository-index <repository-root> <host>")
	}
	root := args[0]
	file, err := os.Open(filepath.Join(root, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read root manifest: %w", err)
	}
	decoded, _, err := manifest.DecodeCanonical(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	index := repositoryindex.Index{SchemaVersion: repositoryindex.SchemaVersion, Targets: []repositoryindex.Target{{Ecosystem: "redevplugin", Host: args[1], Plugins: []repositoryindex.Plugin{{PluginID: decoded.PluginID(), Path: ".", Manifest: "manifest.json", Release: &repositoryindex.Release{TagTemplate: "v{version}", PackageAssetTemplate: "plugin-{version}.redevplugin", ReleaseRefAssetTemplate: "plugin-{version}.release-ref.json"}}}}}}
	if err := repositoryindex.Validate(index); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(repositoryindex.IndexPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := out.Write(append(raw, '\n'))
	closeErr = out.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return writeJSON(map[string]any{"ok": true, "path": path, "note": "Review host and release asset templates before publishing."})
}
