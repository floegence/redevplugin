package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
	"github.com/floegence/redevplugin/pkg/version"
)

type validateSummary struct {
	OK            bool           `json:"ok"`
	Kind          string         `json:"kind"`
	PluginID      string         `json:"plugin_id"`
	Version       string         `json:"version"`
	PackageHash   string         `json:"package_hash,omitempty"`
	ManifestHash  string         `json:"manifest_hash,omitempty"`
	EntriesHash   string         `json:"entries_hash,omitempty"`
	VersionMatrix version.Matrix `json:"version_matrix"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "redevplugin: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "validate":
		if len(args) != 2 {
			return usage()
		}
		return validate(ctx, args[1])
	case "package":
		if len(args) != 3 {
			return usage()
		}
		return buildPackage(ctx, args[1], args[2])
	case "version":
		return writeJSON(version.CurrentMatrix())
	default:
		return usage()
	}
}

func validate(ctx context.Context, filename string) error {
	if strings.HasSuffix(filename, ".redeven-plugin") || strings.HasSuffix(filename, ".zip") {
		pkg, err := pluginpkg.ReadFile(ctx, filename, pluginpkg.DefaultReadOptions())
		if err != nil {
			return err
		}
		return writeJSON(validateSummary{
			OK:            true,
			Kind:          "package",
			PluginID:      pkg.Manifest.PluginID(),
			Version:       pkg.Manifest.Version(),
			PackageHash:   pkg.PackageHash,
			ManifestHash:  pkg.ManifestHash,
			EntriesHash:   pkg.EntriesHash,
			VersionMatrix: version.CurrentMatrix(),
		})
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	decoded, err := manifest.Decode(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return writeJSON(validateSummary{
		OK:            true,
		Kind:          "manifest",
		PluginID:      decoded.PluginID(),
		Version:       decoded.Version(),
		VersionMatrix: version.CurrentMatrix(),
	})
}

func buildPackage(ctx context.Context, srcDir string, outFile string) error {
	if outDir := filepath.Dir(outFile); outDir != "." {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(ctx, srcDir, &buf, pluginpkg.DefaultReadOptions())
	if err != nil {
		return err
	}
	if err := os.WriteFile(outFile, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return writeJSON(validateSummary{
		OK:            true,
		Kind:          "package",
		PluginID:      pkg.Manifest.PluginID(),
		Version:       pkg.Manifest.Version(),
		PackageHash:   pkg.PackageHash,
		ManifestHash:  pkg.ManifestHash,
		EntriesHash:   pkg.EntriesHash,
		VersionMatrix: version.CurrentMatrix(),
	})
}

func writeJSON(v any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func usage() error {
	return fmt.Errorf("usage: redevplugin validate <manifest.json|package.redeven-plugin> | redevplugin package <dir> <out.redeven-plugin> | redevplugin version")
}
