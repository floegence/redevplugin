//go:build linux

package resourceio

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestServiceWatchUsesInotifyAndCloseWakesWaiter(t *testing.T) {
	root := t.TempDir()
	resolver := &fixtureMountResolver{path: root}
	table, err := NewTableWithLimits(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(table, resolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	invocation := fixtureInvocation("watch-session")
	opened := callControl(t, service, invocation, "fs.watch", `{"uri":"redevfs://workspace/","recursive":false}`)
	handle := resultHandle(t, opened, "handle")
	if err := os.WriteFile(filepath.Join(root, "created.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	event := callControl(t, service, invocation, "fs.watch_next", `{"handle":`+jsonNumber(handle)+`,"timeout_ms":2000}`)
	result, ok := event["result"].(map[string]any)
	if event["ok"] != true || !ok || result["kind"] != string(WatchKindCreate) || result["uri"] != "redevfs://workspace/created.txt" {
		t.Fatalf("watch event = %#v", event)
	}

	waiting := make(chan []byte, 1)
	go func() {
		raw, _ := service.Control(context.Background(), invocation, []byte(`{"api":1,"operation":"fs.watch_next","arguments":{"handle":`+jsonNumber(handle)+`,"timeout_ms":5000}}`))
		waiting <- raw
	}()
	time.Sleep(25 * time.Millisecond)
	if err := service.Close(invocation, handle); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-waiting:
		var response map[string]any
		if json.Unmarshal(raw, &response) != nil || response["ok"] != false {
			t.Fatalf("closed watch response = %s", raw)
		}
		errorValue, _ := response["error"].(map[string]any)
		if errorValue["code"] != "RESOURCE_CLOSED" {
			t.Fatalf("closed watch error = %#v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("closing watch did not wake blocked watch_next")
	}
}

func jsonNumber(value uint64) string {
	return strconv.FormatUint(value, 10)
}
