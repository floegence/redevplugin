package resourceio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSelectedDirectoryPagesFitControlEnvelopeWithoutLosingEntries(t *testing.T) {
	dir := t.TempDir()
	for i := range 200 {
		name := fmt.Sprintf("%03d-", i) + strings.Repeat("x", 240)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := OpenSelection(dir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	directory, err := selection.OpenDirectory(URI{MountID: "selected-" + strings.Repeat("a", 64), Path: "."})
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	seen := map[string]bool{}
	for {
		page, err := directory.Next(256)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(controlResponse{OK: true, Result: page})
		if len(raw) > 64<<10 {
			t.Fatalf("oversized control envelope: %d", len(raw))
		}
		for _, entry := range page.Entries {
			if seen[entry.Name] {
				t.Fatal("duplicate entry")
			}
			seen[entry.Name] = true
		}
		if page.EOF {
			break
		}
		if len(page.Entries) == 0 {
			t.Fatal("no progress")
		}
	}
	if len(seen) != 200 {
		t.Fatalf("lost entries: %d", len(seen))
	}
}

type selectedFixtureAuthority struct {
	mu        sync.Mutex
	selection *Selection
	revoked   bool
}

type selectedCopyAuthority struct{ source, target *Selection }

func (a selectedCopyAuthority) WithSelection(_ context.Context, _ Invocation, uri URI, write bool, use func(*Selection) error) error {
	switch uri.MountID {
	case "selected-source":
		if write {
			return os.ErrPermission
		}
		return use(a.source)
	case "selected-target":
		return use(a.target)
	default:
		return os.ErrPermission
	}
}
func TestSelectedCopyChecksSourceReadAndDestinationWrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(source, []byte("copied"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("long original"), 0600); err != nil {
		t.Fatal(err)
	}
	src, err := OpenSelection(source, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := OpenSelection(target, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, nil, nil)
	service.SetSelectedResources(selectedCopyAuthority{src, dst})
	inv := fixtureInvocation("selected-copy")
	inv.Permissions = map[string]bool{PermissionFSSelectedRead: true, PermissionFSSelectedWrite: true}
	response := callControl(t, service, inv, "fs.copy", `{"from":"redevfs://selected-source/","to":"redevfs://selected-target/","overwrite":true}`)
	if response["ok"] != true {
		t.Fatalf("copy: %v", response)
	}
	if data, _ := os.ReadFile(target); string(data) != "copied" {
		t.Fatalf("target=%q", data)
	}
}

func (a *selectedFixtureAuthority) WithSelection(ctx context.Context, invocation Invocation, uri URI, write bool, use func(*Selection) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revoked || uri.MountID != "selected-fixture" || invocation.Owner.Session.OwnerUserHash != "user-hash" {
		return os.ErrPermission
	}
	return use(a.selection)
}

func TestSelectedHandleOutlivesOpeningRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chosen")
	if err := os.WriteFile(path, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err := OpenSelection(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	table, _ := NewTable(2)
	service, _ := NewService(table, nil, nil)
	service.SetSelectedResources(&selectedFixtureAuthority{selection: selection})
	inv := fixtureInvocation("request-selected")
	inv.Owner.Session.OwnerUserHash = "user-hash"
	inv.Permissions = map[string]bool{PermissionFSSelectedRead: true, PermissionFSSelectedWrite: true}
	ctx, cancel := context.WithCancel(context.Background())
	raw, err := service.Control(ctx, inv, []byte(`{"plugin_api":1,"operation":"fs.open","arguments":{"uri":"redevfs://selected-fixture/","options":{"read":true,"write":true}}}`))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	var response map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	handle := resultHandle(t, response, "handle")
	buffer := make([]byte, 9)
	if n, _, err := service.Read(context.Background(), inv, handle, buffer); err != nil || string(buffer[:n]) != "preserved" {
		t.Fatalf("next request: %q %v", buffer, err)
	}
	if _, err := service.Seek(context.Background(), inv, handle, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Write(ctx, inv, handle, []byte("bad"), 0); err != context.Canceled {
		t.Fatalf("canceled write: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "preserved" {
		t.Fatalf("canceled write changed %q", data)
	}
}

func TestSelectedServiceUsesExistingBoundedDataPlane(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chosen")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err := OpenSelection(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	authority := &selectedFixtureAuthority{selection: selection}
	table, _ := NewTableWithLimits(DefaultLimits())
	service, _ := NewService(table, nil, nil)
	service.SetSelectedResources(authority)
	invocation := fixtureInvocation("session-selected")
	invocation.Owner.Session.OwnerUserHash = "user-hash"
	invocation.Permissions = map[string]bool{PermissionFSSelectedRead: true, PermissionFSSelectedWrite: true}
	response := callControl(t, service, invocation, "fs.open", `{"uri":"redevfs://selected-fixture/","options":{"read":true,"write":true}}`)
	handle := resultHandle(t, response, "handle")
	if _, err := service.Write(context.Background(), invocation, handle, []byte("updated!"), 0); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	authority.revoked = true
	authority.mu.Unlock()
	if _, err := service.Write(context.Background(), invocation, handle, []byte("bad"), 0); err == nil {
		t.Fatal("revoked stream wrote")
	}
	if _, _, err := service.Read(context.Background(), invocation, handle, make([]byte, 4)); err == nil {
		t.Fatal("revoked stream read")
	}
	if _, err := service.Seek(context.Background(), invocation, handle, 0, 0); err == nil {
		t.Fatal("revoked stream sought")
	}
	if err := service.Close(invocation, handle); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "updated!" {
		t.Fatalf("bytes=%q", got)
	}
	if r := callControl(t, service, invocation, "fs.open", `{"uri":"redevfs://home/private","options":{"read":true}}`); r["ok"] != false {
		t.Fatalf("selected widened to home: %v", r)
	}
}

func TestSelectedHandleQuotaDoesNotTruncateRejectedOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chosen")
	if err := os.WriteFile(path, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err := OpenSelection(path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Close()
	authority := &selectedFixtureAuthority{selection: selection}
	table, _ := NewTable(1)
	service, _ := NewService(table, nil, nil)
	service.SetSelectedResources(authority)
	inv := fixtureInvocation("quota-selected")
	inv.Owner.Session.OwnerUserHash = "user-hash"
	inv.Permissions = map[string]bool{PermissionFSSelectedRead: true, PermissionFSSelectedWrite: true}
	resultHandle(t, callControl(t, service, inv, "fs.open", `{"uri":"redevfs://selected-fixture/","options":{"read":true}}`), "handle")
	response := callControl(t, service, inv, "fs.open", `{"uri":"redevfs://selected-fixture/","options":{"write":true,"truncate":true}}`)
	if response["ok"] != false {
		t.Fatalf("quota open succeeded: %v", response)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "preserved" {
		t.Fatalf("quota rejection mutated file: %q %v", data, err)
	}
}
