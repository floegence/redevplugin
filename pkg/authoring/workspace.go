package authoring

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
	"github.com/floegence/redevplugin/v3/pkg/pluginpkg"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
	_ "modernc.org/sqlite"
)

var ErrWorkspaceNotFound = errors.New("author workspace not found")
var ErrArtifactNotFound = errors.New("author artifact not found")
var ErrWorkspaceConflict = errors.New("author workspace identity conflict")

// Owner is a stable authenticated user/environment pair, never browser input or
// short-lived Surface authority. Hosts derive it through their session adapter.
type Owner struct {
	User        string `json:"-"`
	Environment string `json:"-"`
}

func (o Owner) valid() bool {
	return o.User != "" && o.Environment != "" && len(o.User) <= 256 && len(o.Environment) <= 256
}

type Workspace struct {
	ID                   string    `json:"workspace_id"`
	SourceDirectory      string    `json:"source_directory"`
	DevelopmentDirectory string    `json:"development_directory"`
	CreatedAt            time.Time `json:"created_at"`
}
type BuildReport struct {
	WorkspaceID string                        `json:"workspace_id"`
	Status      string                        `json:"status"`
	StartedAt   time.Time                     `json:"started_at"`
	Stages      []authorproject.Stage         `json:"stages"`
	Commands    []authorproject.CommandResult `json:"commands"`
	Error       string                        `json:"error,omitempty"`
}

type Artifact struct {
	ID            string                `json:"artifact_id"`
	WorkspaceID   string                `json:"workspace_id"`
	SourceSHA256  string                `json:"source_sha256"`
	PackageSHA256 string                `json:"package_sha256"`
	PluginID      string                `json:"plugin_id"`
	Version       string                `json:"version"`
	CreatedAt     time.Time             `json:"created_at"`
	Stages        []authorproject.Stage `json:"stages"`
}

// WorkspaceStore owns only its explicitly selected root. Source commands are
// never run by opening, observing, inspecting, installing, or deleting artifacts.
type WorkspaceStore struct {
	mu           sync.Mutex
	files        *os.Root
	closed       bool
	environments map[string]*Environment
	builds       map[string]bool
	root         string
	lock         *os.File
	db           *sql.DB
}

const authorSchema = `CREATE TABLE author_schema (id INTEGER PRIMARY KEY CHECK(id=1),kind TEXT NOT NULL,version INTEGER NOT NULL);
INSERT INTO author_schema VALUES(1,'redevplugin_author',1);
CREATE TABLE workspaces(id TEXT PRIMARY KEY,owner_user TEXT NOT NULL,owner_env TEXT NOT NULL,request_id TEXT NOT NULL,created_at INTEGER NOT NULL,deleting INTEGER NOT NULL DEFAULT 0 CHECK(deleting IN (0,1)),UNIQUE(owner_user,owner_env,request_id));
CREATE TABLE artifacts(id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,source_hash TEXT NOT NULL,package_hash TEXT NOT NULL,plugin_id TEXT NOT NULL,version TEXT NOT NULL,created_at INTEGER NOT NULL,stages TEXT NOT NULL);
CREATE TABLE initializations(workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,plugin_id TEXT NOT NULL,display_name TEXT NOT NULL,template TEXT NOT NULL,stage TEXT NOT NULL CHECK(stage IN ('building','prepared','complete')));
CREATE TABLE preview_selection(workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE, active_artifact TEXT NOT NULL DEFAULT '', pending_artifact TEXT NOT NULL DEFAULT '');
CREATE TABLE build_reports(workspace_id TEXT PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE, report TEXT NOT NULL);`

var workspaceIDPattern = regexp.MustCompile(`^author_[A-Z2-7]{26}$`)
var artifactIDPattern = regexp.MustCompile(`^artifact_[A-Z2-7]{26}$`)

// OwnerFromContext derives persistent ownership from the authenticated host
// context. A session refresh never transfers a workspace to another owner.
func OwnerFromContext(ctx context.Context) (Owner, error) {
	session, ok := sessionctx.FromContext(ctx)
	if !ok || !session.Valid() {
		return Owner{}, ErrWorkspaceNotFound
	}
	return Owner{User: session.OwnerUserHash, Environment: session.OwnerEnvHash}, nil
}

func OpenWorkspaceStore(ctx context.Context, root string) (_ *WorkspaceStore, err error) {
	if strings.TrimSpace(root) == "" {
		return nil, ErrWorkspaceConflict
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrWorkspaceConflict
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	s := &WorkspaceStore{root: root}
	s.lock, err = lockAuthorState(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if s.db != nil {
				_ = s.db.Close()
			}
			if s.files != nil {
				_ = s.files.Close()
			}
			_ = s.lock.Close()
		}
	}()
	s.files, err = os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, "author.sqlite")
	stage := filepath.Join(root, ".author-initialize.sqlite")
	// A first database is made durable before publishing its name. On interruption
	// only a complete, exact staged schema may be promoted; unknown bytes stay put.
	if len(entries) == 0 {
		db, e := sql.Open("sqlite", stage)
		if e != nil {
			return nil, e
		}
		_, e = db.ExecContext(ctx, "PRAGMA synchronous=FULL; BEGIN IMMEDIATE;"+authorSchema+"COMMIT;")
		err = errors.Join(e, db.Close())
		if err != nil {
			return nil, err
		}
		if err = s.lock.Sync(); err != nil {
			return nil, err
		}
		entries, err = os.ReadDir(root)
		if err != nil {
			return nil, err
		}
	}
	if len(entries) == 1 && entries[0].Name() == ".author-initialize.sqlite" {
		if err = validateAuthorDatabase(ctx, stage); err != nil {
			return nil, err
		}
		if err = s.files.Rename(".author-initialize.sqlite", "author.sqlite"); err != nil {
			return nil, err
		}
		if err = s.lock.Sync(); err != nil {
			return nil, err
		}
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "author.sqlite", "author.sqlite-journal", "projects", ".author-initialize.sqlite":
		default:
			return nil, ErrWorkspaceConflict
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrWorkspaceConflict
		}
	}
	if err = validateAuthorDatabase(ctx, path); err != nil {
		return nil, err
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}).String()
	s.db, err = sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	s.db.SetMaxOpenConns(1)
	_, err = s.db.ExecContext(ctx, "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT w.id,w.owner_user,w.owner_env,i.plugin_id,i.display_name,i.template FROM workspaces w JOIN initializations i ON i.workspace_id=w.id WHERE w.deleting=0 AND i.stage!='complete'")
	if err != nil {
		return nil, err
	}
	type pendingInit struct {
		id                     string
		owner                  Owner
		plugin, name, template string
	}
	pending := []pendingInit{}
	for rows.Next() {
		var p pendingInit
		if err = rows.Scan(&p.id, &p.owner.User, &p.owner.Environment, &p.plugin, &p.name, &p.template); err != nil {
			rows.Close()
			return nil, err
		}
		pending = append(pending, p)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	for _, p := range pending {
		if _, err = s.Initialize(ctx, p.owner, p.id, p.plugin, p.name, p.template); err != nil {
			return nil, err
		}
	}
	if err = s.recoverBuildReports(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
func validateAuthorDatabase(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ErrWorkspaceConflict
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String())
	if err != nil {
		return err
	}
	defer db.Close()
	var kind, check string
	var version, count int
	if db.QueryRowContext(ctx, "SELECT kind,version FROM author_schema WHERE id=1").Scan(&kind, &version) != nil || kind != "redevplugin_author" || version != 1 {
		return ErrWorkspaceConflict
	}
	if db.QueryRowContext(ctx, "SELECT count(*) FROM author_schema").Scan(&count) != nil || count != 1 {
		return ErrWorkspaceConflict
	}
	if db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" {
		return ErrWorkspaceConflict
	}
	expected, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer expected.Close()
	if _, err = expected.ExecContext(ctx, authorSchema); err != nil {
		return err
	}
	shape := func(database *sql.DB) ([]string, error) {
		rows, e := database.QueryContext(ctx, "SELECT type||':'||name||':'||tbl_name||':'||sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		result := []string{}
		for rows.Next() {
			var raw string
			if e = rows.Scan(&raw); e != nil {
				return nil, e
			}
			result = append(result, raw)
		}
		return result, rows.Err()
	}
	actual, err := shape(db)
	if err != nil {
		return err
	}
	want, err := shape(expected)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, want) {
		return ErrWorkspaceConflict
	}
	return nil
}
func (s *WorkspaceStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.builds) > 0 {
		return errors.New("author builds are still running")
	}
	if len(s.environments) > 0 {
		return errors.New("close author environments before closing workspace store")
	}
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.db.Close(), s.files.Close(), s.lock.Close())
}
func (s *WorkspaceStore) workspace(id string, created int64) Workspace {
	return Workspace{ID: id, SourceDirectory: filepath.Join(s.root, "projects", id, "source"), DevelopmentDirectory: filepath.Join(s.root, "projects", id, "development"), CreatedAt: time.Unix(0, created).UTC()}
}
func (s *WorkspaceStore) Create(ctx context.Context, owner Owner, requestID string) (Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !owner.valid() || strings.TrimSpace(requestID) == "" || len(requestID) > 160 {
		return Workspace{}, ErrWorkspaceConflict
	}
	var id string
	var created int64
	var deleting bool
	err := s.db.QueryRowContext(ctx, "SELECT id,created_at,deleting FROM workspaces WHERE owner_user=? AND owner_env=? AND request_id=?", owner.User, owner.Environment, requestID).Scan(&id, &created, &deleting)
	if err == nil {
		if deleting {
			return Workspace{}, ErrWorkspaceConflict
		}
		return s.ensureSource(s.workspace(id, created))
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, err
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM workspaces WHERE owner_user=? AND owner_env=?", owner.User, owner.Environment).Scan(&count); err != nil {
		return Workspace{}, err
	}
	if count >= 10000 {
		return Workspace{}, errors.New("author workspace receipt capacity reached")
	}
	id = "author_" + rand.Text()
	created = time.Now().UTC().UnixNano()
	if _, err = s.db.ExecContext(ctx, "INSERT INTO workspaces(id,owner_user,owner_env,request_id,created_at) VALUES(?,?,?,?,?)", id, owner.User, owner.Environment, requestID, created); err != nil {
		return Workspace{}, err
	}
	return s.ensureSource(s.workspace(id, created))
}
func (s *WorkspaceStore) ensureSource(w Workspace) (Workspace, error) {
	if !workspaceIDPattern.MatchString(w.ID) {
		return Workspace{}, ErrWorkspaceConflict
	}
	return w, s.files.MkdirAll(filepath.Join("projects", w.ID, "source"), 0700)
}
func (s *WorkspaceStore) Get(ctx context.Context, owner Owner, id string) (Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(ctx, owner, id)
}
func (s *WorkspaceStore) get(ctx context.Context, owner Owner, id string) (Workspace, error) {
	if !owner.valid() || !workspaceIDPattern.MatchString(id) {
		return Workspace{}, ErrWorkspaceNotFound
	}
	var created int64
	if err := s.db.QueryRowContext(ctx, "SELECT created_at FROM workspaces WHERE id=? AND owner_user=? AND owner_env=? AND deleting=0", id, owner.User, owner.Environment).Scan(&created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Workspace{}, ErrWorkspaceNotFound
		}
		return Workspace{}, err
	}
	w := s.workspace(id, created)
	for _, path := range []string{"projects", filepath.Join("projects", id), filepath.Join("projects", id, "source")} {
		info, e := s.files.Lstat(path)
		if e != nil {
			return Workspace{}, e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return Workspace{}, ErrWorkspaceConflict
		}
	}
	return w, nil
}
func (s *WorkspaceStore) Initialize(ctx context.Context, owner Owner, id, pluginID, name, template string) (TemplateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !owner.valid() || !workspaceIDPattern.MatchString(id) {
		return TemplateResult{}, ErrWorkspaceNotFound
	}
	var created int64
	if err := s.db.QueryRowContext(ctx, "SELECT created_at FROM workspaces WHERE id=? AND owner_user=? AND owner_env=? AND deleting=0", id, owner.User, owner.Environment).Scan(&created); err != nil {
		return TemplateResult{}, ErrWorkspaceNotFound
	}
	w := s.workspace(id, created)
	staged := filepath.Join("projects", id, "initializing")
	source := filepath.Join("projects", id, "source")
	var savedID, savedName, savedTemplate, stage string
	err := s.db.QueryRowContext(ctx, "SELECT plugin_id,display_name,template,stage FROM initializations WHERE workspace_id=?", id).Scan(&savedID, &savedName, &savedTemplate, &stage)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err = s.get(ctx, owner, id); err != nil {
			return TemplateResult{}, err
		}
		entries, e := os.ReadDir(w.SourceDirectory)
		if e != nil {
			return TemplateResult{}, e
		}
		if len(entries) != 0 {
			return TemplateResult{}, ErrWorkspaceConflict
		}
		if _, err = s.db.ExecContext(ctx, "INSERT INTO initializations VALUES(?,?,?,?,'building')", id, pluginID, name, template); err != nil {
			return TemplateResult{}, err
		}
		stage = "building"
	} else if err != nil {
		return TemplateResult{}, err
	} else if savedID != pluginID || savedName != name || savedTemplate != template {
		return TemplateResult{}, ErrWorkspaceConflict
	}
	result := TemplateResult{OK: true, Kind: "plugin_scaffold", PluginID: pluginID, Version: "0.1.0", OutputDir: w.SourceDirectory, Files: []string{}}
	if stage == "complete" {
		return result, nil
	}
	if stage == "building" {
		if err = s.files.RemoveAll(staged); err != nil {
			return result, err
		}
		result, err = Init(pluginID, name, filepath.Join(s.root, staged), template)
		if err != nil {
			return result, err
		}
		if err = filepath.WalkDir(filepath.Join(s.root, staged), func(path string, entry os.DirEntry, failure error) error {
			if failure != nil {
				return failure
			}
			if !entry.Type().IsRegular() && !entry.IsDir() {
				return ErrWorkspaceConflict
			}
			f, e := os.Open(path)
			if e != nil {
				return e
			}
			return errors.Join(f.Sync(), f.Close())
		}); err != nil {
			return result, err
		}
		if err = s.syncDirectory(filepath.Join("projects", id)); err != nil {
			return result, err
		}
		if _, err = s.db.ExecContext(ctx, "UPDATE initializations SET stage='prepared' WHERE workspace_id=?", id); err != nil {
			return result, err
		}
	}
	if _, err = s.files.Lstat(staged); err == nil {
		// Only an empty source directory may be replaced. A failed partial scaffold
		// stays in the reserved staging directory and is never exposed to tools.
		if err = s.files.Remove(source); err != nil && !os.IsNotExist(err) {
			return result, err
		}
		if err = s.files.Rename(staged, source); err != nil {
			return result, err
		}
	} else if !os.IsNotExist(err) {
		return result, err
	}
	if err = s.syncDirectory(filepath.Join("projects", id)); err != nil {
		return result, err
	}
	if _, err = s.get(ctx, owner, id); err != nil {
		return result, err
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE initializations SET stage='complete' WHERE workspace_id=?", id); err != nil {
		return result, err
	}
	result.OutputDir = w.SourceDirectory
	return result, nil
}
func (s *WorkspaceStore) syncDirectory(path string) error {
	f, err := s.files.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func (s *WorkspaceStore) Build(ctx context.Context, owner Owner, id string, options authorproject.PipelineOptions) (_ Artifact, err error) {
	s.mu.Lock()
	w, err := s.get(ctx, owner, id)
	if err != nil {
		s.mu.Unlock()
		return Artifact{}, err
	}
	if s.builds == nil {
		s.builds = map[string]bool{}
	}
	if s.builds[id] {
		s.mu.Unlock()
		return Artifact{}, errors.New("author build is already running")
	}
	report := BuildReport{WorkspaceID: id, Status: "running", StartedAt: time.Now().UTC(), Stages: []authorproject.Stage{}, Commands: []authorproject.CommandResult{}}
	if err = s.saveBuildReport(ctx, report); err != nil {
		s.mu.Unlock()
		return Artifact{}, err
	}
	s.builds[id] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.builds, id)
		report.Status = "passed"
		if err != nil {
			report.Status = "failed"
			report.Error = err.Error()
		}
		err = errors.Join(err, s.saveBuildReport(context.WithoutCancel(ctx), report))
	}()
	project, err := authorproject.Load(w.SourceDirectory)
	if err != nil {
		return Artifact{}, err
	}
	result, err := project.Build(ctx, options)
	report.Stages = result.Stages
	report.Commands = result.Commands
	if err != nil {
		return Artifact{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveArtifact(ctx, w, result)
}

func (s *WorkspaceStore) saveBuildReport(ctx context.Context, report BuildReport) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO build_reports VALUES(?,?) ON CONFLICT(workspace_id) DO UPDATE SET report=excluded.report", report.WorkspaceID, string(raw))
	return err
}

// BuildReport returns the latest actual build attempt independently of the last
// successful artifact. A process interruption never turns a running check green.
func (s *WorkspaceStore) BuildReport(ctx context.Context, owner Owner, id string) (*BuildReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.get(ctx, owner, id); err != nil {
		return nil, err
	}
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT report FROM build_reports WHERE workspace_id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var report BuildReport
	err = json.Unmarshal([]byte(raw), &report)
	return &report, err
}
func (s *WorkspaceStore) recoverBuildReports(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT report FROM build_reports")
	if err != nil {
		return err
	}
	var pending []BuildReport
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var report BuildReport
		if err = json.Unmarshal([]byte(raw), &report); err != nil {
			break
		}
		if report.Status == "running" {
			report.Status = "interrupted"
			report.Error = "Build interrupted before a durable result"
			pending = append(pending, report)
		}
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	for _, report := range pending {
		if err = s.saveBuildReport(ctx, report); err != nil {
			return err
		}
	}
	return nil
}

// Capture validates existing output without running project commands. The normal
// author check/build tool must complete first; source hashes describe provenance,
// while package hashes bind the immutable bytes used by preview and inspection.
func (s *WorkspaceStore) Capture(ctx context.Context, owner Owner, id string) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.get(ctx, owner, id)
	if err != nil {
		return Artifact{}, err
	}
	p, err := authorproject.Load(w.SourceDirectory)
	if err != nil {
		return Artifact{}, err
	}
	before, err := p.Snapshot(ctx)
	if err != nil {
		return Artifact{}, err
	}
	pkg, raw, err := p.Package(ctx)
	if err != nil {
		return Artifact{}, err
	}
	after, err := p.Snapshot(ctx)
	if err != nil {
		return Artifact{}, err
	}
	source, err := os.ReadFile(filepath.Join(p.Root, "manifest.json"))
	if err != nil {
		return Artifact{}, err
	}
	_, canonical, err := manifest.DecodeCanonical(bytes.NewReader(source))
	if err != nil {
		return Artifact{}, err
	}
	packaged, err := manifest.MarshalCanonical(pkg.Manifest)
	if err != nil {
		return Artifact{}, err
	}
	if !bytes.Equal(canonical, packaged) {
		return Artifact{}, errors.New("packaged manifest differs from source; rebuild first")
	}
	if before != after {
		return Artifact{}, ErrWorkspaceConflict
	}
	return s.saveArtifact(ctx, w, authorproject.PipelineResult{Package: pkg, Bytes: raw, SourceHash: before, Stages: []authorproject.Stage{{Name: "package", Status: "passed"}}})
}
func (s *WorkspaceStore) saveArtifact(ctx context.Context, w Workspace, result authorproject.PipelineResult) (Artifact, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM artifacts WHERE workspace_id=?", w.ID).Scan(&count); err != nil {
		return Artifact{}, err
	}
	if count >= 256 {
		return Artifact{}, errors.New("author artifact capacity reached; create a new workspace")
	}
	a := Artifact{ID: "artifact_" + rand.Text(), WorkspaceID: w.ID, SourceSHA256: result.SourceHash, PackageSHA256: result.Package.PackageHash, PluginID: result.Package.Manifest.PluginID(), Version: result.Package.Manifest.Version(), CreatedAt: time.Now().UTC(), Stages: result.Stages}
	dir := filepath.Join("projects", w.ID, "artifacts")
	if err := s.files.MkdirAll(dir, 0700); err != nil {
		return Artifact{}, err
	}
	path := filepath.Join(dir, a.ID+".redevplugin")
	f, err := s.files.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Artifact{}, err
	}
	_, writeErr := f.Write(result.Bytes)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return Artifact{}, err
	}
	directory, err := s.files.Open(dir)
	if err != nil {
		return Artifact{}, err
	}
	err = errors.Join(directory.Sync(), directory.Close())
	if err != nil {
		return Artifact{}, err
	}
	stages, err := json.Marshal(a.Stages)
	if err != nil {
		return Artifact{}, err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?)", a.ID, a.WorkspaceID, a.SourceSHA256, a.PackageSHA256, a.PluginID, a.Version, a.CreatedAt.UnixNano(), string(stages))
	return a, err
}
func (s *WorkspaceStore) ListArtifacts(ctx context.Context, owner Owner, id string) ([]Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listArtifacts(ctx, owner, id)
}
func (s *WorkspaceStore) listArtifacts(ctx context.Context, owner Owner, id string) ([]Artifact, error) {
	if _, err := s.get(ctx, owner, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,source_hash,package_hash,plugin_id,version,created_at,stages FROM artifacts WHERE workspace_id=? ORDER BY created_at DESC,id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Artifact{}
	for rows.Next() {
		var a Artifact
		var created int64
		var stages string
		a.WorkspaceID = id
		if err = rows.Scan(&a.ID, &a.SourceSHA256, &a.PackageSHA256, &a.PluginID, &a.Version, &created, &stages); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(stages), &a.Stages); err != nil {
			return nil, err
		}
		if !artifactIDPattern.MatchString(a.ID) {
			return nil, ErrWorkspaceConflict
		}
		a.CreatedAt = time.Unix(0, created).UTC()
		result = append(result, a)
	}
	return result, rows.Err()
}
func (s *WorkspaceStore) ReadArtifact(ctx context.Context, owner Owner, workspaceID, artifactID string) (Artifact, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !artifactIDPattern.MatchString(artifactID) {
		return Artifact{}, nil, ErrArtifactNotFound
	}
	all, err := s.listArtifacts(ctx, owner, workspaceID)
	if err != nil {
		return Artifact{}, nil, err
	}
	for _, a := range all {
		if a.ID != artifactID {
			continue
		}
		path := filepath.Join("projects", workspaceID, "artifacts", artifactID+".redevplugin")
		info, err := s.files.Lstat(path)
		if err != nil {
			return Artifact{}, nil, err
		}
		if !info.Mode().IsRegular() {
			return Artifact{}, nil, ErrWorkspaceConflict
		}
		f, err := s.files.Open(path)
		if err != nil {
			return Artifact{}, nil, err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return Artifact{}, nil, ErrWorkspaceConflict
		}
		raw, err := io.ReadAll(io.LimitReader(f, 256<<20+1))
		if err != nil {
			return Artifact{}, nil, err
		}
		if len(raw) > 256<<20 {
			return Artifact{}, nil, ErrWorkspaceConflict
		}
		pkg, err := pluginpkg.Read(ctx, bytes.NewReader(raw), int64(len(raw)), pluginpkg.DefaultReadLimits())
		if err != nil {
			return Artifact{}, nil, err
		}
		if pkg.PackageHash != a.PackageSHA256 || pkg.Manifest.PluginID() != a.PluginID || pkg.Manifest.Version() != a.Version {
			return Artifact{}, nil, ErrWorkspaceConflict
		}
		return a, raw, nil
	}
	return Artifact{}, nil, ErrArtifactNotFound
}
func (s *WorkspaceStore) InspectArtifact(ctx context.Context, owner Owner, workspaceID, artifactID string, h *host.Host, intent host.ExternalPackageIntent) (host.ExternalPackageInspection, error) {
	authenticated, err := OwnerFromContext(ctx)
	if err != nil || authenticated != owner {
		return host.ExternalPackageInspection{}, ErrWorkspaceNotFound
	}
	_, raw, err := s.ReadArtifact(ctx, owner, workspaceID, artifactID)
	if err != nil {
		return host.ExternalPackageInspection{}, err
	}
	return h.InspectUploadedExternalPackage(ctx, host.InspectUploadedExternalPackageRequest{Intent: intent, Package: bytes.NewReader(raw), DeclaredSize: int64(len(raw))})
}

// Remove requires the caller to first close its preview Host and stop source
// tools. It deletes only this store's generated directory, never an input path.
// A tombstone makes an interrupted deletion resumable without resurrecting it.
func (s *WorkspaceStore) Remove(ctx context.Context, owner Owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !owner.valid() || !workspaceIDPattern.MatchString(id) {
		return ErrWorkspaceNotFound
	}
	if s.builds[id] {
		return errors.New("stop author build before deleting workspace")
	}
	if _, open := s.environments[id]; open {
		return errors.New("close author environment before deleting workspace")
	}
	var known string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM workspaces WHERE id=? AND owner_user=? AND owner_env=?", id, owner.User, owner.Environment).Scan(&known)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = s.db.ExecContext(ctx, "UPDATE workspaces SET deleting=1 WHERE id=?", id); err != nil {
		return err
	}
	if !workspaceIDPattern.MatchString(known) {
		return ErrWorkspaceConflict
	}
	if err = s.files.RemoveAll(filepath.Join("projects", known)); err != nil {
		return fmt.Errorf("remove author workspace: %w", err)
	}
	if err = s.lock.Sync(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, "DELETE FROM initializations WHERE workspace_id=?", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM artifacts WHERE workspace_id=?", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM preview_selection WHERE workspace_id=?", id); err != nil {
		return err
	}
	// Retain the create receipt so a delayed retry cannot resurrect deleted source.
	return tx.Commit()
}
