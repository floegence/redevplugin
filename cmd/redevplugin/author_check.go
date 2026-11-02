package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/authorapi"
	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

type authorDiagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func runAuthorCheck(ctx context.Context, root string, doctor bool) error {
	diagnostics := []authorDiagnostic{}
	add := func(code, path, message string) {
		diagnostics = append(diagnostics, authorDiagnostic{code, path, message})
	}
	project, err := authorproject.Load(root)
	if err != nil {
		add("PROJECT_INVALID", "redevplugin.project.json", err.Error())
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	var m manifest.Manifest
	if err != nil {
		add("MANIFEST_UNAVAILABLE", "manifest.json", err.Error())
	} else {
		m, _, err = manifest.DecodeCanonical(bytes.NewReader(raw))
		if err != nil {
			add("MANIFEST_INVALID", "manifest.json", err.Error())
		}
	}
	if err == nil {
		files, err := authorapi.Generate(raw)
		if err != nil {
			add("BINDING_INVALID", "manifest.json", err.Error())
		} else {
			if _, err := os.Stat(filepath.Join(root, "generated")); err == nil {
				names := make([]string, 0, len(files))
				for name := range files {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					value, err := os.ReadFile(filepath.Join(root, "generated", name))
					if err != nil || !bytes.Equal(value, files[name]) {
						add("BINDING_STALE", "generated/"+name, "Run redevplugin generate manifest.json generated")
					}
				}
			}
		}
	}
	tools := map[string]bool{}
	if project != nil {
		for _, argv := range [][]string{project.Config.Build, project.Config.Test} {
			_, err := exec.LookPath(argv[0])
			tools[argv[0]] = err == nil
			if err != nil {
				add("TOOL_UNAVAILABLE", argv[0], "Install the project's declared build/test tool")
			}
		}
		if !doctor && len(diagnostics) == 0 {
			for _, stage := range []struct {
				name string
				args []string
			}{{"build", project.Config.Build}, {"test", project.Config.Test}} {
				result, err := project.Run(ctx, stage.args)
				if err != nil {
					add("COMMAND_FAILED", stage.name, result.Output)
					break
				}
			}
			if len(diagnostics) == 0 {
				built, readErr := os.ReadFile(filepath.Join(project.Root, project.Config.Output, "manifest.json"))
				_, sourceCanonical, sourceErr := manifest.DecodeCanonical(bytes.NewReader(raw))
				_, builtCanonical, builtErr := manifest.DecodeCanonical(bytes.NewReader(built))
				if readErr != nil || sourceErr != nil || builtErr != nil || !bytes.Equal(sourceCanonical, builtCanonical) {
					add("MANIFEST_DRIFT", project.Config.Output+"/manifest.json", "Build output must match the canonical source manifest")
				}
			}
			if len(diagnostics) == 0 {
				if _, _, err := project.Package(ctx); err != nil {
					add("PACKAGE_INVALID", project.Config.Output, err.Error())
				}
			}
		}
	}
	report := map[string]any{"ok": len(diagnostics) == 0, "command": "check", "diagnostics": diagnostics, "tools": tools, "runtime_required": len(m.Workers) > 0, "note": "Tool presence is not runtime admission. Worker preview requires an explicitly verified runtime; check runs only this selected project's build and tests."}
	if doctor {
		report["command"] = "doctor"
	}
	if err := writeJSON(report); err != nil {
		return err
	}
	if len(diagnostics) > 0 {
		return errors.New("author project needs attention; see diagnostics")
	}
	return nil
}
