// Package authorproject runs explicitly selected local plugin source projects.
// Installed plugin archives never execute these author-controlled commands.
package authorproject

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
)

const ConfigFile = "redevplugin.project.json"
const SchemaVersion = "redevplugin.project.v1"
const maxSourceBytes = 64 << 20
const maxSourceFiles = 10000

// Config describes build inputs, never production permissions or package trust.
type Config struct {
	SchemaVersion string   `json:"schema_version"`
	Output        string   `json:"output"`
	Build         []string `json:"build"`
	Test          []string `json:"test"`
	Watch         []string `json:"watch"`
}

type Project struct {
	Root       string
	Config     Config
	configHash [32]byte
}

func readConfig(root string) ([]byte, error) {
	path := filepath.Join(root, ConfigFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("project configuration must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("project configuration exceeds 64 KiB")
	}
	return raw, nil
}

func Load(root string) (*Project, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	raw, err := readConfig(absolute)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ConfigFile, err)
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("project configuration exceeds 64 KiB")
	}
	// Duplicate fields are ambiguous even when encoding/json would accept them.
	tokens := json.NewDecoder(bytes.NewReader(raw))
	token, err := tokens.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("project configuration must be an object")
	}
	seen := map[string]bool{}
	for tokens.More() {
		key, err := tokens.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return nil, errors.New("duplicate project field")
		}
		switch name {
		case "schema_version", "output", "build", "test", "watch":
		default:
			return nil, fmt.Errorf("unknown project field: %s", name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := tokens.Decode(&value); err != nil {
			return nil, err
		}
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing project content")
	}
	if config.SchemaVersion != SchemaVersion {
		return nil, errors.New("unsupported project schema_version")
	}
	if !localPath(config.Output) || config.Output == "." {
		return nil, errors.New("output must be a project-relative directory")
	}
	for _, command := range [][]string{config.Build, config.Test} {
		if len(command) == 0 || len(command) > 64 || strings.TrimSpace(command[0]) == "" {
			return nil, errors.New("build and test must be nonempty argv arrays")
		}
		for _, arg := range command {
			if strings.ContainsRune(arg, 0) || utf8.RuneCountInString(arg) > 8192 {
				return nil, errors.New("invalid command argument")
			}
		}
	}
	if len(config.Watch) == 0 || len(config.Watch) > 64 {
		return nil, errors.New("watch requires 1 to 64 relative inputs")
	}
	watchSeen := map[string]bool{}
	for _, input := range config.Watch {
		if !localPath(input) || input == "." || watchSeen[input] || containsPath(input, config.Output) || containsPath(config.Output, input) {
			return nil, errors.New("watch inputs must be unique, relative, and separate from output")
		}
		watchSeen[input] = true
	}
	p := &Project{Root: absolute, Config: config, configHash: sha256.Sum256(raw)}
	if err := p.checkOutput(); err != nil {
		return nil, err
	}
	return p, nil
}

func localPath(path string) bool {
	return filepath.IsLocal(path) && filepath.ToSlash(filepath.Clean(path)) == path && !strings.ContainsAny(path, "\\\x00")
}
func containsPath(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+"/")
}
func (p *Project) checkOutput() error {
	current := p.Root
	for _, part := range strings.Split(p.Config.Output, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output must contain only real directories")
		}
	}
	return nil
}

// Snapshot hashes only bounded regular source inputs and rejects symlinks.
func (p *Project) Snapshot(ctx context.Context) (string, error) {
	raw, err := readConfig(p.Root)
	if err != nil {
		return "", err
	}
	if sha256.Sum256(raw) != p.configHash {
		return "", errors.New("project configuration changed; restart the developer preview to apply it")
	}
	inputs := append([]string{ConfigFile}, p.Config.Watch...)
	sort.Strings(inputs)
	h := sha256.New()
	var total int64
	files := 0
	for _, input := range inputs {
		ancestor := p.Root
		for _, part := range strings.Split(input, "/") {
			ancestor = filepath.Join(ancestor, part)
			info, err := os.Lstat(ancestor)
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			if err != nil {
				return "", err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("watch path contains a symlink: %s", input)
			}
		}
		full := filepath.Join(p.Root, filepath.FromSlash(input))
		err := filepath.WalkDir(full, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if errors.Is(walkErr, os.ErrNotExist) {
				_, _ = fmt.Fprintf(h, "missing:%s;", input)
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("watch input is a symlink: %s", path)
			}
			if d.IsDir() {
				if path != full && (d.Name() == "node_modules" || d.Name() == "target" || d.Name() == ".git") {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return errors.New("watch inputs must be regular files")
			}
			files++
			total += info.Size()
			if files > maxSourceFiles || total > maxSourceBytes {
				return errors.New("watch inputs exceed the 10000 file / 64 MiB budget")
			}
			relative, err := filepath.Rel(p.Root, path)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(h, "%s:%d:%d;", filepath.ToSlash(relative), info.Mode(), info.Size())
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(h, io.LimitReader(file, maxSourceBytes+1))
			return errors.Join(copyErr, file.Close())
		})
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type CommandResult struct {
	Arguments  []string `json:"arguments"`
	Output     string   `json:"output"`
	Truncated  bool     `json:"truncated"`
	DurationMS int64    `json:"duration_ms"`
}
type boundedOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(value)
	limit := 64 << 10
	if len(b.data)+n > limit {
		b.truncated = true
		keep := limit - len(b.data)
		if keep > 0 {
			b.data = append(b.data, value[:keep]...)
		}
	} else {
		b.data = append(b.data, value...)
	}
	return n, nil
}

// Run executes argv directly, with no implicit shell or downloaded command.
func (p *Project) Run(ctx context.Context, argv []string) (CommandResult, error) {
	if len(argv) == 0 {
		return CommandResult{}, errors.New("command is required")
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	command.Dir = p.Root
	command.WaitDelay = 2 * time.Second
	configureCommandCancellation(command)
	output := &boundedOutput{}
	command.Stdout = output
	command.Stderr = output
	start := time.Now()
	err := command.Run()
	finishCommand(command)
	result := CommandResult{Arguments: append([]string(nil), argv...), Output: string(output.data), Truncated: output.truncated, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		return result, fmt.Errorf("command %q failed: %w", argv[0], err)
	}
	return result, nil
}

// Package builds an immutable validated archive from the selected output.
func (p *Project) Package(ctx context.Context) (pluginpkg.Package, []byte, error) {
	if err := p.checkOutput(); err != nil {
		return pluginpkg.Package{}, nil, err
	}
	var archive bytes.Buffer
	pkg, err := pluginpkg.BuildFromDir(ctx, filepath.Join(p.Root, p.Config.Output), &archive, pluginpkg.DefaultReadLimits())
	if err != nil {
		return pluginpkg.Package{}, nil, err
	}
	return pkg, append([]byte(nil), archive.Bytes()...), nil
}
