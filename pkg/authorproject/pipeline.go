package authorproject

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/authorapi"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

// Stage records actual checks without treating a test command as runtime evidence.
type Stage struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
}
type PipelineOptions struct {
	Identity pluginidentity.Identity
	Generate bool
	Test     bool
}
type PipelineResult struct {
	Package    pluginpkg.Package
	Bytes      []byte
	SourceHash string
	Commands   []CommandResult
	Stages     []Stage
}
type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string { return fmt.Sprintf("%s: %v", e.Stage, e.Err) }
func (e *StageError) Unwrap() error { return e.Err }

// Build validates one source generation before exposing a candidate package.
// Development regenerates only explicitly configured tool-managed bindings.
func (p *Project) Build(ctx context.Context, options PipelineOptions) (result PipelineResult, err error) {
	result.Commands = []CommandResult{}
	result.Stages = []Stage{}
	run := func(name string, fn func() error) error {
		start := time.Now()
		failure := fn()
		status := "passed"
		if failure != nil {
			status = "failed"
		}
		result.Stages = append(result.Stages, Stage{name, status, time.Since(start).Milliseconds()})
		if failure != nil {
			return &StageError{name, failure}
		}
		return nil
	}
	if _, err = p.Snapshot(ctx); err != nil {
		return result, &StageError{"source", err}
	}
	if len(p.Config.Prepare) > 0 {
		if err = run("prepare", func() error {
			value, failure := p.Run(ctx, p.Config.Prepare)
			result.Commands = append(result.Commands, value)
			return failure
		}); err != nil {
			return
		}
	}
	if err = run("source", func() error { var failure error; result.SourceHash, failure = p.Snapshot(ctx); return failure }); err != nil {
		return
	}
	var source []byte
	if err = run("manifest", func() error {
		var failure error
		source, failure = os.ReadFile(filepath.Join(p.Root, "manifest.json"))
		if failure != nil {
			return failure
		}
		if options.Identity.PluginID != "" || options.Identity.PublisherID != "" {
			_, source, failure = manifest.CompileSource(source, options.Identity)
		} else {
			_, source, failure = manifest.DecodeAuthorCanonical(bytes.NewReader(source))
		}
		return failure
	}); err != nil {
		return
	}
	directory := p.Config.Bindings
	if directory == "" {
		if info, failure := os.Lstat(filepath.Join(p.Root, "generated")); failure == nil && info.IsDir() {
			directory = "generated"
		}
	}
	if directory != "" {
		if err = run("bindings", func() error {
			return authorapi.WriteIdentity(filepath.Join(p.Root, "manifest.json"), filepath.Join(p.Root, directory), !options.Generate || p.Config.Bindings == "", options.Identity)
		}); err != nil {
			return
		}
	}
	for _, command := range []struct {
		name    string
		argv    []string
		enabled bool
	}{{"typecheck", p.Config.Typecheck, len(p.Config.Typecheck) > 0}, {"build", p.Config.Build, true}, {"declared-tests", p.Config.Test, options.Test}} {
		if !command.enabled {
			result.Stages = append(result.Stages, Stage{command.name, "not_run", 0})
			continue
		}
		if err = run(command.name, func() error {
			value, failure := p.Run(ctx, command.argv)
			result.Commands = append(result.Commands, value)
			return failure
		}); err != nil {
			return
		}
	}
	err = run("package", func() error {
		built, failure := os.ReadFile(filepath.Join(p.Root, p.Config.Output, "manifest.json"))
		if failure != nil {
			return failure
		}
		_, a, failure := manifest.DecodeAuthorCanonical(bytes.NewReader(source))
		if failure != nil {
			return failure
		}
		_, b, failure := manifest.DecodeCanonical(bytes.NewReader(built))
		if failure != nil {
			return failure
		}
		if !bytes.Equal(a, b) {
			return errors.New("packaged manifest differs from source; rebuild from the current manifest")
		}
		result.Package, result.Bytes, failure = p.Package(ctx)
		return failure
	})
	if err != nil {
		return
	}
	err = run("source-consistency", func() error {
		current, failure := p.Snapshot(ctx)
		if failure != nil {
			return failure
		}
		if current != result.SourceHash {
			return errors.New("source changed during build; waiting for the next complete build")
		}
		if directory != "" {
			return authorapi.WriteIdentity(filepath.Join(p.Root, "manifest.json"), filepath.Join(p.Root, directory), true, options.Identity)
		}
		return nil
	})
	if err != nil {
		result.Bytes = nil
	}
	return
}
