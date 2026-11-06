// Package repositoryindex parses the host-neutral repository discovery contract.
// It deliberately does not search GitHub, execute repository code, or execute plugins.
package repositoryindex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginidentity"
	"github.com/floegence/redevplugin/v3/pkg/version"
)

const (
	SchemaVersion = "redevplugin.repository-index.v1"
	IndexPath     = ".redevplugin/index.json"
	MaxBytes      = 256 << 10
	MaxTargets    = 32
	MaxPlugins    = 256
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	tagPattern        = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*-v\{version\}$`)
	templatePattern   = regexp.MustCompile(`^[A-Za-z0-9._+@-]*\{version\}[A-Za-z0-9._+@-]*$`)
	assetPattern      = regexp.MustCompile(`^[A-Za-z0-9._+@-]+(?:\{version\}[A-Za-z0-9._+@-]*)?$`)
	pathPartPattern   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
)

type Index struct {
	RepositoryID  int64    `json:"-"`
	Schema        string   `json:"$schema,omitempty"`
	SchemaVersion string   `json:"schema_version"`
	Targets       []Target `json:"targets"`
}

type Target struct {
	Ecosystem string   `json:"ecosystem"`
	Host      string   `json:"host"`
	Plugins   []Plugin `json:"plugins"`
}

type Plugin struct {
	Slug     string   `json:"slug"`
	PluginID string   `json:"plugin_id,omitempty"`
	Path     string   `json:"path"`
	Manifest string   `json:"manifest"`
	Release  *Release `json:"release,omitempty"`
}

type Release struct {
	TagTemplate          string `json:"tag_template"`
	PackageAssetTemplate string `json:"package_asset_template"`
}

type Entry struct {
	Target Target `json:"-"`
	Plugin Plugin `json:"plugin"`
}

type Repository struct {
	Root      string
	Index     Index
	Canonical []byte
	SHA256    string
	RawSHA256 string
	Entries   []Entry
}

func Decode(raw []byte) (Index, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return Index{}, fmt.Errorf("repository index must be between 1 and %d bytes", MaxBytes)
	}
	if !utf8.Valid(raw) {
		return Index{}, errors.New("repository index must be UTF-8")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return Index{}, err
	}
	if err := validateJSONShape(raw); err != nil {
		return Index{}, err
	}
	var value Index
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Index{}, fmt.Errorf("decode repository index: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Index{}, errors.New("repository index must contain exactly one JSON value")
	}
	if err := Validate(value); err != nil {
		return Index{}, err
	}
	return value, nil
}

func Load(root string) (Repository, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Repository{}, err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return Repository{}, fmt.Errorf("resolve repository root: %w", err)
	}
	indexFile, err := repositoryPath(absolute, ".", IndexPath)
	if err != nil {
		return Repository{}, fmt.Errorf("resolve %s: %w", IndexPath, err)
	}
	file, err := os.Open(indexFile)
	if err != nil {
		return Repository{}, fmt.Errorf("read %s: %w", IndexPath, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return Repository{}, fmt.Errorf("read %s: %w", IndexPath, err)
	}
	index, err := Decode(raw)
	if err != nil {
		return Repository{}, err
	}
	canonical, err := json.Marshal(index)
	if err != nil {
		return Repository{}, fmt.Errorf("canonicalize repository index: %w", err)
	}
	repo := Repository{Root: absolute, Index: index, Canonical: canonical, SHA256: sha256Hex(canonical), RawSHA256: sha256Hex(raw)}
	for _, target := range index.Targets {
		for _, plugin := range target.Plugins {
			repo.Entries = append(repo.Entries, Entry{Target: target, Plugin: plugin})
		}
	}
	return repo, nil
}

func Validate(value Index) error {
	if value.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %s", SchemaVersion)
	}
	if len(value.Targets) == 0 || len(value.Targets) > MaxTargets {
		return fmt.Errorf("targets must contain between 1 and %d items", MaxTargets)
	}
	seenTargets := make(map[string]struct{}, len(value.Targets))
	pluginCount := 0
	byID := map[string]Plugin{}
	byTag := map[string]string{}
	for targetIndex, target := range value.Targets {
		if target.Ecosystem != "redevplugin" || !identifierPattern.MatchString(target.Host) {
			return fmt.Errorf("targets[%d] has an invalid ecosystem or host", targetIndex)
		}
		targetKey := target.Ecosystem + "\x00" + target.Host
		if _, ok := seenTargets[targetKey]; ok {
			return fmt.Errorf("targets[%d] duplicates ecosystem and host", targetIndex)
		}
		seenTargets[targetKey] = struct{}{}
		if len(target.Plugins) == 0 || len(target.Plugins) > MaxPlugins {
			return fmt.Errorf("targets[%d].plugins must be non-empty and bounded", targetIndex)
		}
		seenIDs := make(map[string]struct{}, len(target.Plugins))
		for pluginIndex, plugin := range target.Plugins {
			pluginCount++
			if pluginCount > MaxPlugins {
				return fmt.Errorf("repository index contains more than %d plugins", MaxPlugins)
			}
			if pluginidentity.ValidateSlug(plugin.Slug) != nil {
				return fmt.Errorf("targets[%d].plugins[%d].slug is invalid", targetIndex, pluginIndex)
			}
			if value.RepositoryID == 0 {
				if plugin.PluginID != "" {
					return errors.New("repository index declares slug only; plugin_id is generated")
				}
			} else {
				identity, err := pluginidentity.GitHub(value.RepositoryID, plugin.Slug)
				if err != nil || identity.PluginID != plugin.PluginID {
					return errors.New("resolved plugin identity does not match repository")
				}
			}
			if _, ok := seenIDs[plugin.Slug]; ok {
				return fmt.Errorf("targets[%d] duplicates slug %q", targetIndex, plugin.Slug)
			}
			seenIDs[plugin.Slug] = struct{}{}
			if !safeRelativePath(plugin.Path) || plugin.Manifest == "." || !safeRelativePath(plugin.Manifest) {
				return fmt.Errorf("targets[%d].plugins[%d] contains an unsafe path", targetIndex, pluginIndex)
			}
			if plugin.Release == nil {
				return fmt.Errorf("targets[%d].plugins[%d].release is required for redevplugin", targetIndex, pluginIndex)
			}
			if err := validateRelease(*plugin.Release); err != nil {
				return fmt.Errorf("targets[%d].plugins[%d].release: %w", targetIndex, pluginIndex, err)
			}
			if previous, exists := byTag[plugin.Release.TagTemplate]; exists && previous != plugin.Slug {
				return fmt.Errorf("plugins %q and %q share a release namespace", previous, plugin.Slug)
			}
			if previous, exists := byID[plugin.Slug]; exists && (previous.Path != plugin.Path || previous.Manifest != plugin.Manifest || *previous.Release != *plugin.Release) {
				return fmt.Errorf("plugin %q has inconsistent declarations across targets", plugin.Slug)
			}
			byTag[plugin.Release.TagTemplate] = plugin.Slug
			byID[plugin.Slug] = plugin
		}
	}
	return nil
}

func (repo Repository) Find(ecosystem, host string) []Entry {
	entries := make([]Entry, 0)
	for _, entry := range repo.Entries {
		if entry.Target.Ecosystem != "redevplugin" {
			continue
		}
		if entry.Target.Ecosystem == ecosystem && entry.Target.Host == host {
			entries = append(entries, entry)
		}
	}
	return entries
}

// EntryDigest binds one plugin and its target independently of sibling entries.
func EntryDigest(host string, plugin Plugin) (string, error) {
	value := Index{SchemaVersion: SchemaVersion, Targets: []Target{{Ecosystem: "redevplugin", Host: host, Plugins: []Plugin{plugin}}}}
	if err := Validate(value); err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		Ecosystem     string `json:"ecosystem"`
		Host          string `json:"host"`
		Plugin        Plugin `json:"plugin"`
	}{SchemaVersion, "redevplugin", host, plugin})
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}

func ValidateRepository(root string) (Repository, error) {
	repo, err := Load(root)
	if err != nil {
		return Repository{}, err
	}
	for _, entry := range repo.Entries {
		if err := validatePluginManifest(repo.Root, entry.Plugin); err != nil {
			return Repository{}, err
		}
	}
	return repo, nil
}

func validatePluginManifest(root string, plugin Plugin) error {
	path, err := repositoryPath(root, plugin.Path, plugin.Manifest)
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("plugin %q manifest: %w", plugin.Slug, err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	decoded, _, decodeErr := manifest.CompileSource(raw, pluginidentity.Identity{})
	decodeErr = errors.Join(readErr, decodeErr)
	closeErr := file.Close()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return err
	}
	if decoded.PluginID() != plugin.Slug {
		return fmt.Errorf("plugin %q does not match manifest slug %q", plugin.Slug, decoded.PluginID())
	}
	return nil
}

func Render(template, version string) (string, error) {
	if len(template) > 255 || !assetPattern.MatchString(template) {
		return "", errors.New("release template is invalid")
	}
	if _, err := versionpkgParseStable(version); err != nil {
		return "", errors.New("release version is invalid")
	}
	result := strings.ReplaceAll(template, "{version}", version)
	if len(result) > 255 {
		return "", errors.New("rendered release name exceeds 255 bytes")
	}
	return result, nil
}

// VersionFromTag matches the complete tag and extracts a stable SemVer.
func VersionFromTag(template, tag string) (string, error) {
	if len(template) > 255 || !tagPattern.MatchString(template) || len(tag) > 255 {
		return "", errors.New("release template or tag is invalid")
	}
	parts := strings.Split(template, "{version}")
	if !strings.HasPrefix(tag, parts[0]) || !strings.HasSuffix(tag, parts[1]) || len(tag) < len(parts[0])+len(parts[1]) {
		return "", errors.New("release tag does not match template")
	}
	value := tag[len(parts[0]) : len(tag)-len(parts[1])]
	if _, err := versionpkgParseStable(value); err != nil {
		return "", errors.New("release tag does not contain a stable version")
	}
	return value, nil
}

func versionpkgParseStable(value string) (version.SemVer, error) {
	if strings.ContainsAny(value, "+-") {
		return version.SemVer{}, errors.New("version is not stable")
	}
	return version.ParseSemVer(value)
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func validateRelease(value Release) error {
	if !tagPattern.MatchString(value.TagTemplate) {
		return errors.New("tag_template must be <release-key>-v{version}")
	}
	if !strings.HasSuffix(value.PackageAssetTemplate, ".redevplugin") {
		return errors.New("package asset must end in .redevplugin")
	}
	for name, template := range map[string]string{
		"tag_template":           value.TagTemplate,
		"package_asset_template": value.PackageAssetTemplate,
	} {
		if len(template) > 255 || (name == "tag_template" && !templatePattern.MatchString(template)) || (name == "package_asset_template" && !assetPattern.MatchString(template)) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func safeRelativePath(value string) bool {
	if len(value) > 512 {
		return false
	}
	if value == "." {
		return true
	}
	if value == "" || filepath.IsAbs(value) || strings.ContainsAny(value, `\\:`) || strings.HasPrefix(value, "./") || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || !pathPartPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func repositoryPath(root, pluginPath, manifestPath string) (string, error) {
	if !safeRelativePath(pluginPath) || (!safeRelativePath(manifestPath) && manifestPath != IndexPath) {
		return "", errors.New("path is not safe")
	}
	candidate := filepath.Join(root, filepath.FromSlash(pluginPath), filepath.FromSlash(manifestPath))
	current := root
	for _, part := range strings.Split(filepath.ToSlash(strings.TrimPrefix(candidate, root+string(filepath.Separator))), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("repository paths must not contain symlinks")
		}
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("manifest is not a regular file")
	}
	return candidate, nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return fmt.Errorf("invalid repository index JSON: %w", err)
	}
	return nil
}

// Validate exact field names and JSON types before decoding into Go structs,
// whose decoder otherwise accepts case-insensitive names and null strings.
func validateJSONShape(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	object := func(value any, required, optional []string) (map[string]any, error) {
		fields, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("expected JSON object")
		}
		allowed := make(map[string]bool, len(required)+len(optional))
		for _, key := range append(required, optional...) {
			allowed[key] = true
		}
		for key := range fields {
			if !allowed[key] {
				return nil, fmt.Errorf("unknown field %q", key)
			}
		}
		for _, key := range required {
			if _, ok := fields[key]; !ok {
				return nil, fmt.Errorf("missing field %q", key)
			}
		}
		return fields, nil
	}
	stringField := func(fields map[string]any, key string) error {
		if _, ok := fields[key].(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
		return nil
	}
	root, err := object(value, []string{"schema_version", "targets"}, []string{"$schema"})
	if err != nil {
		return err
	}
	if err := stringField(root, "schema_version"); err != nil {
		return err
	}
	if _, ok := root["$schema"]; ok {
		if err := stringField(root, "$schema"); err != nil {
			return err
		}
	}
	targets, ok := root["targets"].([]any)
	if !ok {
		return errors.New("targets must be an array")
	}
	for _, item := range targets {
		target, err := object(item, []string{"ecosystem", "host", "plugins"}, nil)
		if err != nil {
			return err
		}
		for _, key := range []string{"ecosystem", "host"} {
			if err := stringField(target, key); err != nil {
				return err
			}
		}
		plugins, ok := target["plugins"].([]any)
		if !ok {
			return errors.New("plugins must be an array")
		}
		for _, item := range plugins {
			plugin, err := object(item, []string{"slug", "path", "manifest", "release"}, nil)
			if err != nil {
				return err
			}
			for _, key := range []string{"slug", "path", "manifest"} {
				if err := stringField(plugin, key); err != nil {
					return err
				}
			}
			release, err := object(plugin["release"], []string{"tag_template", "package_asset_template"}, nil)
			if err != nil {
				return err
			}
			for key := range release {
				if err := stringField(release, key); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func SortedEntries(repo Repository) []Entry {
	entries := append([]Entry(nil), repo.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Plugin.Slug < entries[j].Plugin.Slug })
	return entries
}

// ResolveGitHub binds raw author entries to an independently observed repository.
// The raw index remains slug-only and is never rewritten in the source repository.
func ResolveGitHub(index Index, repositoryID int64) (Index, error) {
	if err := Validate(index); err != nil {
		return Index{}, err
	}
	if index.RepositoryID != 0 {
		return Index{}, errors.New("repository index is already resolved")
	}
	resolved := index
	resolved.RepositoryID = repositoryID
	resolved.Targets = append([]Target(nil), index.Targets...)
	for i, target := range index.Targets {
		resolved.Targets[i].Plugins = append([]Plugin(nil), target.Plugins...)
		for j, p := range target.Plugins {
			identity, err := pluginidentity.GitHub(repositoryID, p.Slug)
			if err != nil {
				return Index{}, err
			}
			resolved.Targets[i].Plugins[j].PluginID = identity.PluginID
		}
	}
	return resolved, Validate(resolved)
}
