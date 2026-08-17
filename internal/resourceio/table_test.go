package resourceio

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/redevplugin/v3/pkg/sessionctx"
)

type testResource struct{ strings.Reader }

func (testResource) Close() error { return nil }

func testOwner(session string) Owner {
	scope := sessionctx.SessionScope{OwnerSessionHash: session, OwnerUserHash: "user", OwnerEnvHash: "env", SessionChannelIDHash: "channel-" + session}
	resourceScope := sessionctx.ResourceScope{Kind: sessionctx.ScopeUser, OwnerEnvHash: "env", OwnerUserHash: "user"}
	return Owner{PluginInstanceID: "plugin", ActiveFingerprint: "fingerprint", Scope: resourceScope, Session: scope, RuntimeGeneration: "generation", Lifetime: LifetimeSession}
}

func TestResourceHandleFitsSignedWASMABI(t *testing.T) {
	handle := resourceHandleFromEntropy([8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if handle == 0 || uint64(handle) > math.MaxInt64 {
		t.Fatalf("resource handle = %d, want 1..%d", handle, uint64(math.MaxInt64))
	}
}

func TestTableBindsExactSessionAndClosesOnRevoke(t *testing.T) {
	table, err := NewTable(4)
	if err != nil {
		t.Fatal(err)
	}
	first := testOwner("session-a")
	second := testOwner("session-b")
	handle, err := table.Open(first, KindTCP, testResource{Reader: *strings.NewReader("ok")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Read(context.Background(), handle, second, make([]byte, 2)); err != ErrOwnerMismatch {
		t.Fatalf("cross-session read error = %v, want ErrOwnerMismatch", err)
	}
	if err := table.Revoke(func(owner Owner) bool { return owner.Session.OwnerSessionHash == first.Session.OwnerSessionHash }); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Read(context.Background(), handle, first, make([]byte, 2)); err != ErrResourceClosed {
		t.Fatalf("revoked read error = %v, want ErrResourceClosed", err)
	}
}

func TestTableRejectsPartialWriteAndSupportsIdempotentClose(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	resource := &writeResource{}
	handle, err := table.Open(owner, KindFile, resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Write(context.Background(), handle, owner, make([]byte, 64<<10+1)); err != ErrResourceLimit {
		t.Fatalf("oversized write error = %v, want ErrResourceLimit", err)
	}
	if err := table.Close(handle, owner); err != nil {
		t.Fatal(err)
	}
	if err := table.Close(handle, owner); err != nil {
		t.Fatal(err)
	}
}

func TestTableProjectsEOFWithoutReturningAnError(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	handle, err := table.Open(owner, KindFile, &testResource{Reader: *strings.NewReader("")})
	if err != nil {
		t.Fatal(err)
	}
	n, flags, err := table.ReadChunk(context.Background(), handle, owner, make([]byte, 1))
	if err != nil || n != 0 || flags != IOFlagEOF {
		t.Fatalf("EOF read = (%d, %d, %v)", n, flags, err)
	}
}

type writeResource struct{}

func (*writeResource) Write(value []byte) (int, error) { return len(value), nil }
func (*writeResource) Close() error                    { return nil }

var _ io.Writer = (*writeResource)(nil)

type blockingResource struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (resource *blockingResource) Read([]byte) (int, error) {
	close(resource.started)
	<-resource.closed
	return 0, io.ErrClosedPipe
}

func (resource *blockingResource) Close() error {
	resource.once.Do(func() { close(resource.closed) })
	return nil
}

func TestTableCloseWinsAndWakesBlockedRead(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	resource := &blockingResource{started: make(chan struct{}), closed: make(chan struct{})}
	handle, err := table.Open(owner, KindTCP, resource)
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := table.Read(context.Background(), handle, owner, make([]byte, 1))
		readResult <- readErr
	}()
	select {
	case <-resource.started:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	if err := table.Close(handle, owner); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, ErrResourceClosed) {
			t.Fatalf("blocked read error = %v, want ErrResourceClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake blocked read")
	}
}

func TestTableSerializesOperationsPerHandle(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	resource := &serialResource{entered: make(chan struct{}, 2), release: make(chan struct{})}
	handle, err := table.Open(owner, KindFile, resource)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, readErr := table.Read(context.Background(), handle, owner, make([]byte, 1))
			results <- readErr
		}()
	}
	<-resource.entered
	select {
	case <-resource.entered:
		t.Fatal("two operations entered the resource concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	resource.release <- struct{}{}
	<-resource.entered
	resource.release <- struct{}{}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

func TestTableAllowsFullDuplexReadAndWriteWhileKeepingEachDirectionSerialized(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	resource := &duplexResource{readStarted: make(chan struct{}), releaseRead: make(chan struct{}), wrote: make(chan struct{})}
	handle, err := table.Open(owner, KindTCP, resource)
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := table.Read(context.Background(), handle, owner, make([]byte, 1))
		readResult <- readErr
	}()
	<-resource.readStarted
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := table.Write(context.Background(), handle, owner, []byte{1})
		writeResult <- writeErr
	}()
	select {
	case <-resource.wrote:
	case <-time.After(time.Second):
		t.Fatal("full-duplex write was blocked behind read")
	}
	close(resource.releaseRead)
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
}

func TestTableAllowsFullDuplexControlWhileReadIsBlocked(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	resource := &duplexResource{readStarted: make(chan struct{}), releaseRead: make(chan struct{}), wrote: make(chan struct{})}
	handle, err := table.Open(owner, KindTCP, resource)
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := table.Read(context.Background(), handle, owner, make([]byte, 1))
		readResult <- readErr
	}()
	<-resource.readStarted
	controlResult := make(chan error, 1)
	go func() {
		controlResult <- table.UseControl(handle, owner, KindTCP, func(io.Closer) error { return nil })
	}()
	select {
	case err := <-controlResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("full-duplex control was blocked behind read")
	}
	close(resource.releaseRead)
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
}

func TestTableClosesHandleWhenTrustedAuthorityChanges(t *testing.T) {
	table, err := NewTable(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := testOwner("session")
	resource := &recordingCloseResource{Reader: *strings.NewReader("ok")}
	handle, err := table.Open(owner, KindFile, resource)
	if err != nil {
		t.Fatal(err)
	}
	stale := owner
	stale.RevokeEpoch++
	if _, err := table.Read(context.Background(), handle, stale, make([]byte, 1)); !errors.Is(err, ErrResourceClosed) {
		t.Fatalf("stale authority read error = %v, want ErrResourceClosed", err)
	}
	if resource.closeCount != 1 || table.Len() != 0 {
		t.Fatalf("stale handle close count = %d, table len = %d", resource.closeCount, table.Len())
	}
}

func TestTableDefaultLimitsArePerPluginAndScope(t *testing.T) {
	if _, err := NewTableWithLimits(Limits{FileHandles: MinimumFileHandles - 1, Connections: MinimumConnections, WatchesListeners: MinimumWatchesListeners}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("lowered platform limit error = %v, want ErrResourceLimit", err)
	}
	table, err := NewTableWithLimits(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	first := testOwner("session-a")
	for range MinimumFileHandles {
		if _, err := table.Open(first, KindFile, &writeResource{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := table.Open(first, KindFile, &writeResource{}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("file limit error = %v, want ErrResourceLimit", err)
	}
	second := first
	second.PluginInstanceID = "plugin-two"
	if _, err := table.Open(second, KindFile, &writeResource{}); err != nil {
		t.Fatalf("another plugin must retain its resource guarantee: %v", err)
	}
}

type recordingCloseResource struct {
	strings.Reader
	closeCount int
}

func (resource *recordingCloseResource) Close() error {
	resource.closeCount++
	return nil
}

type serialResource struct {
	entered chan struct{}
	release chan struct{}
}

func (resource *serialResource) Read(destination []byte) (int, error) {
	resource.entered <- struct{}{}
	<-resource.release
	destination[0] = 1
	return 1, nil
}

func (*serialResource) Close() error { return nil }

type duplexResource struct {
	readStarted chan struct{}
	releaseRead chan struct{}
	wrote       chan struct{}
}

func (*duplexResource) FullDuplexResource() {}
func (resource *duplexResource) Read(destination []byte) (int, error) {
	close(resource.readStarted)
	<-resource.releaseRead
	destination[0] = 1
	return 1, nil
}
func (resource *duplexResource) Write(source []byte) (int, error) {
	close(resource.wrote)
	return len(source), nil
}
func (*duplexResource) Close() error { return nil }
