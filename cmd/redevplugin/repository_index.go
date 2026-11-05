package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"

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
		Ecosystem   string                 `json:"ecosystem"`
		Host        string                 `json:"host"`
		Plugin      repositoryindex.Plugin `json:"plugin"`
		EntrySHA256 string                 `json:"entry_sha256"`
	}
	entries := make([]entry, 0, len(repo.Entries))
	for _, item := range repo.Entries {
		digest, err := repositoryindex.EntryDigest(item.Target.Host, item.Plugin)
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
	if len(args) < 2 {
		return errors.New("usage: redevplugin scaffold repository-index <repository-root> <host> --project <path> --tag-template <key>-v{version} --package-asset-template <name> [--manifest manifest.json] [--replace]")
	}
	flags := flag.NewFlagSet("repository-index", flag.ContinueOnError)
	project := flags.String("project", ".", "Plugin project path relative to the repository")
	manifestPath := flags.String("manifest", "manifest.json", "Manifest path relative to the plugin project")
	tag := flags.String("tag-template", "", "Release tag template")
	asset := flags.String("package-asset-template", "", "Package asset template")
	replace := flags.Bool("replace", false, "Replace the selected plugin entry")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected repository-index arguments")
	}
	changed, err := repositoryindex.Upsert(args[0], args[1], *project, *manifestPath, repositoryindex.Release{TagTemplate: *tag, PackageAssetTemplate: *asset}, *replace)
	if err != nil {
		return err
	}
	return writeJSON(map[string]any{"ok": true, "path": filepath.Join(args[0], repositoryindex.IndexPath), "changed": changed})
}
