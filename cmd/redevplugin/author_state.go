package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/authorproject"
	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type authorStateRecord struct {
	Schema      string `json:"schema"`
	Project     string `json:"project"`
	User        string `json:"user"`
	Environment string `json:"environment"`
	Session     string `json:"session"`
	Channel     string `json:"channel"`
}
type authorState struct {
	root       string
	persistent bool
	record     authorStateRecord
	lock       *os.File
}

func openAuthorState(project *authorproject.Project, path string) (_ *authorState, err error) {
	state := &authorState{}
	if path == "" {
		state.root, err = os.MkdirTemp("", "redevplugin-author-")
		return state, err
	}
	root, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// The directory is selected explicitly and must never alias source/output.
	if root == project.Root || withinAuthorPath(root, project.Root) || withinAuthorPath(project.Root, root) {
		return nil, errors.New("persistent development state must be outside the source project")
	}
	if info, failure := os.Lstat(root); failure == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("development state must be a real directory")
		}
	} else if !os.IsNotExist(failure) {
		return nil, failure
	} else if err = os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	root = resolved
	if root == project.Root || withinAuthorPath(root, project.Root) || withinAuthorPath(project.Root, root) {
		return nil, errors.New("persistent state aliases the source project")
	}
	state.root = root
	state.persistent = true
	state.lock, err = lockAuthorState(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = state.close()
		}
	}()
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	marker := filepath.Join(root, "author-state.json")
	raw, readErr := readAuthorStateMarker(marker)
	// A complete staged first marker is recoverable after interruption before rename.
	if os.IsNotExist(readErr) && len(entries) == 1 && strings.HasPrefix(entries[0].Name(), ".author-state-") {
		staged := filepath.Join(root, entries[0].Name())
		candidate, failure := readAuthorStateMarker(staged)
		if failure == nil && decodeAuthorState(candidate, project.Root, &state.record) == nil {
			if err = os.Rename(staged, marker); err != nil {
				return nil, err
			}
			if err = state.lock.Sync(); err != nil {
				return nil, err
			}
			raw, readErr = candidate, nil
		}
	}
	if readErr != nil && (!os.IsNotExist(readErr) || len(entries) != 0) {
		return nil, errors.New("unrecognized development state; existing bytes were not changed")
	}
	if readErr == nil {
		info, failure := os.Lstat(marker)
		if failure != nil || !info.Mode().IsRegular() {
			return nil, errors.New("invalid development state marker")
		}
		if decodeAuthorState(raw, project.Root, &state.record) != nil {
			return nil, errors.New("development state identity does not match this project")
		}
	}
	if readErr != nil {
		state.record = authorStateRecord{Schema: "redevplugin.author-state.v1", Project: project.Root, User: rand.Text(), Environment: rand.Text(), Session: rand.Text(), Channel: rand.Text()}
		if err = state.save(); err != nil {
			return nil, err
		}
	}
	return state, nil
}
func withinAuthorPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && filepath.IsLocal(relative)
}
func (r authorStateRecord) session() sessionctx.Context {
	return sessionctx.Context{OwnerUserHash: r.User, OwnerEnvHash: r.Environment, OwnerSessionHash: r.Session, SessionChannelIDHash: r.Channel, CanRead: true, CanWrite: true}
}
func (s *authorState) save() error {
	raw, err := json.Marshal(s.record)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.root, ".author-state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(s.root, "author-state.json")); err != nil {
		return err
	}
	return s.lock.Sync()
}
func (s *authorState) renew() sessionctx.Context {
	s.record.Session = rand.Text()
	s.record.Channel = rand.Text()
	return s.record.session()
}
func (s *authorState) close() error {
	if !s.persistent {
		return os.RemoveAll(s.root)
	}
	if s.lock != nil {
		return s.lock.Close()
	}
	return nil
}
func closeAuthorSession(ctx context.Context, h *host.Host, session sessionctx.Context) error {
	result, err := h.CloseAuthenticatedSessionScope(ctx, host.CloseAuthenticatedSessionScopeRequest{Session: session})
	if err != nil {
		return err
	}
	if result.Status != host.SessionScopeTeardownComplete {
		return fmt.Errorf("development session cleanup incomplete: %s", result.Status)
	}
	_, err = h.FinalizeClosedSessionScope(ctx, host.FinalizeClosedSessionScopeRequest{Session: session, Identity: result.Identity})
	return err
}

func readAuthorStateMarker(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8192 {
		return nil, errors.New("invalid development state marker")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("development state marker changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 {
		return nil, errors.New("development state marker exceeds limit")
	}
	return raw, nil
}

func decodeAuthorState(raw []byte, project string, record *authorStateRecord) error {
	tokens := json.NewDecoder(bytes.NewReader(raw))
	token, err := tokens.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid development marker")
	}
	seen := map[string]bool{}
	for tokens.More() {
		key, err := tokens.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return errors.New("duplicate development marker key")
		}
		switch name {
		case "schema", "project", "user", "environment", "session", "channel":
		default:
			return errors.New("unknown development marker key")
		}
		seen[name] = true
		var value string
		if err := tokens.Decode(&value); err != nil {
			return err
		}
	}
	if len(seen) != 6 {
		return errors.New("incomplete development marker")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(record) != nil || decoder.Decode(new(any)) != io.EOF || record.Schema != "redevplugin.author-state.v1" || record.Project != project || !record.session().Valid() {
		return errors.New("development marker identity mismatch")
	}
	return nil
}
