package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"

	"github.com/floegence/redevplugin/v3/pkg/authorapi"
	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
)

func generateAuthorAPI(input, output string, check bool) error {
	if err := authorapi.Write(input, output, check); err != nil {
		return err
	}
	return writeJSON(map[string]any{"ok": true, "checked": check, "files": []string{"actions.rs", "actions.ts", "manifest.json", "source-map.json"}})
}

func authorPublication(ctx context.Context, input, repository string, release bool) (pluginidentity.Identity, error) {
	if !release {
		if repository != "" {
			return pluginidentity.Identity{}, errors.New("--repository requires --release")
		}
		return pluginidentity.Identity{}, nil
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		return pluginidentity.Identity{}, err
	}
	m, _, err := manifest.CompileSource(raw, pluginidentity.Identity{})
	if err != nil {
		return pluginidentity.Identity{}, err
	}
	return resolvePublicationIdentity(ctx, filepath.Dir(input), repository, m.PluginID())
}

func runAuthorGenerate(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: redevplugin generate <manifest.json> <output-dir> [--check] [--release] [--repository <url>]")
	}
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	check := flags.Bool("check", false, "check generated bindings without changing files")
	release := flags.Bool("release", false, "resolve GitHub publication identity before generating bindings")
	repository := flags.String("repository", "", "GitHub repository URL; defaults to Git origin")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected generate arguments")
	}
	identity, err := authorPublication(ctx, args[0], *repository, *release)
	if err != nil {
		return err
	}
	if err = authorapi.WriteIdentity(args[0], args[1], *check, identity); err != nil {
		return err
	}
	return writeJSON(map[string]any{"ok": true, "checked": *check, "files": []string{"actions.rs", "actions.ts", "manifest.json", "source-map.json"}})
}

func runAuthorBuild(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: redevplugin build <project-root> [--release] [--repository <url>] [--test]")
	}
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	release := flags.Bool("release", false, "resolve GitHub publication identity before building")
	repository := flags.String("repository", "", "GitHub repository URL; defaults to Git origin")
	test := flags.Bool("test", false, "run declared project tests")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected build arguments")
	}
	project, err := authorproject.Load(args[0])
	if err != nil {
		return err
	}
	identity, err := authorPublication(ctx, filepath.Join(project.Root, "manifest.json"), *repository, *release)
	if err != nil {
		return err
	}
	result, err := project.Build(ctx, authorproject.PipelineOptions{Generate: true, Test: *test, Identity: identity})
	if err != nil {
		return err
	}
	if _, _, err = manifest.DecodeCanonical(bytes.NewReader(result.Package.CanonicalManifestBytes)); err != nil {
		return err
	}
	return writeJSON(map[string]any{"ok": true, "plugin_id": result.Package.Manifest.PluginID(), "stages": result.Stages, "source_sha256": result.SourceHash, "package_sha256": result.Package.PackageHash})
}
