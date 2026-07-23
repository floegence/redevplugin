package externalsource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("reader must not be called")
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(value []byte) (int, error) {
	read, err := reader.reader.Read(value)
	reader.read += read
	return read, err
}

type readerFunc func([]byte) (int, error)

func (read readerFunc) Read(value []byte) (int, error) { return read(value) }

type blockingReader struct {
	started chan<- struct{}
	release <-chan struct{}
	once    sync.Once
	done    bool
}

func (reader *blockingReader) Read(value []byte) (int, error) {
	if reader.done {
		return 0, io.EOF
	}
	reader.once.Do(func() {
		reader.started <- struct{}{}
		<-reader.release
	})
	reader.done = true
	value[0] = 'x'
	return 1, nil
}

func buildMinimalPackage(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	_, err := pluginpkg.BuildFromDir(context.Background(), filepath.Join("..", "..", "testdata", "generated_plugins", "minimal"), &archive, pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func TestStageStoreStagesAndVerifiesExactPackageBytes(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	artifact, err := store.Stage(context.Background(), bytes.NewReader(buildMinimalPackage(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Remove(artifact) })

	info, err := os.Lstat(filepath.Join(directory, stageFilename(artifact.ID)))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}
	pkg, err := store.VerifyPackage(context.Background(), artifact, pluginpkg.DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pkg.Manifest.Plugin.PluginID, "com.example.minimal"; got != want {
		t.Fatalf("plugin ID = %q, want %q", got, want)
	}
}

func TestStageStoreRejectsTamperedArtifact(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	artifact, err := store.Stage(context.Background(), bytes.NewReader(buildMinimalPackage(t)))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, stageFilename(artifact.ID))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = store.VerifyPackage(context.Background(), artifact, pluginpkg.DefaultReadLimits())
	if CodeOf(err) != ErrorStageIntegrity {
		t.Fatalf("code=%q err=%v", CodeOf(err), err)
	}
}

func TestStageStoreCleansCancelledAndOversizedWrites(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.Stage(ctx, bytes.NewReader([]byte("data")))
	if CodeOf(err) != ErrorTransport {
		t.Fatalf("cancel code=%q err=%v", CodeOf(err), err)
	}
	_, err = store.stageWithLimit(context.Background(), bytes.NewReader([]byte("12345")), 4)
	if CodeOf(err) != ErrorArtifactTooLarge {
		t.Fatalf("large code=%q err=%v", CodeOf(err), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("stage entries=%v err=%v", entries, err)
	}
}

func TestStageStoreEnforcesOwnerAndGlobalByteQuotas(t *testing.T) {
	store, err := NewStageStoreWithOptions(t.TempDir(), StageStoreOptions{
		MaxConcurrentFetches: 4, MaxOwnerConcurrentFetches: 2,
		MaxStagedBytes: 8, MaxOwnerStagedBytes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ownerA, err := store.stageWithLimitForOwner(context.Background(), "owner-a", bytes.NewReader([]byte("1234")), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.stageWithLimitForOwner(context.Background(), "owner-a", bytes.NewReader([]byte("x")), 2); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("owner quota error code = %q, err = %v", CodeOf(err), err)
	}
	ownerB, err := store.stageWithLimitForOwner(context.Background(), "owner-b", bytes.NewReader([]byte("5678")), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.stageWithLimitForOwner(context.Background(), "owner-c", bytes.NewReader([]byte("x")), 1); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("global quota error code = %q, err = %v", CodeOf(err), err)
	}
	if err := store.Remove(ownerA); err != nil {
		t.Fatal(err)
	}
	replacement, err := store.stageWithLimitForOwner(context.Background(), "owner-a", bytes.NewReader([]byte("x")), 1)
	if err != nil {
		t.Fatalf("quota was not released after remove: %v", err)
	}
	for _, artifact := range []StagedArtifact{ownerB, replacement} {
		if err := store.Remove(artifact); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStageStoreReleasesFailedWriteReservation(t *testing.T) {
	store, err := NewStageStoreWithOptions(t.TempDir(), StageStoreOptions{
		MaxConcurrentFetches: 1, MaxOwnerConcurrentFetches: 1,
		MaxStagedBytes: 2, MaxOwnerStagedBytes: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.stageWithLimitForOwner(context.Background(), "owner", bytes.NewReader([]byte("123")), 2); CodeOf(err) != ErrorArtifactTooLarge {
		t.Fatalf("oversized write code = %q, err = %v", CodeOf(err), err)
	}
	artifact, err := store.stageWithLimitForOwner(context.Background(), "owner", bytes.NewReader([]byte("12")), 2)
	if err != nil {
		t.Fatalf("failed write leaked its quota reservation: %v", err)
	}
	t.Cleanup(func() { _ = store.Remove(artifact) })
}

func TestStageUploadRejectsKnownEmptyAndOversizedDeclarationsBeforeReading(t *testing.T) {
	store, err := NewStageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.StageUpload(context.Background(), "owner", panicReader{}, 0); CodeOf(err) != ErrorArtifactEmpty {
		t.Fatalf("empty declaration code = %q, err = %v", CodeOf(err), err)
	}
	if _, err := store.StageUpload(context.Background(), "owner", panicReader{}, MaxArtifactBytes+1); CodeOf(err) != ErrorArtifactTooLarge {
		t.Fatalf("oversized declaration code = %q, err = %v", CodeOf(err), err)
	}

	artifact, err := store.StageUpload(context.Background(), "owner", strings.NewReader("x"), 1)
	if err != nil {
		t.Fatalf("preflight rejection leaked transfer quota: %v", err)
	}
	if err := store.Remove(artifact); err != nil {
		t.Fatal(err)
	}
}

func TestStageUploadBoundsKnownAndUnknownStreams(t *testing.T) {
	for _, test := range []struct {
		name         string
		declaredSize int64
	}{
		{name: "known", declaredSize: 2},
		{name: "unknown", declaredSize: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			store, err := NewStageStoreWithOptions(directory, StageStoreOptions{
				MaxConcurrentFetches: 1, MaxOwnerConcurrentFetches: 1,
				MaxStagedBytes: 4, MaxOwnerStagedBytes: 4,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })

			source := &countingReader{reader: strings.NewReader("123456789")}
			if _, err := store.stageUploadWithLimit(context.Background(), "owner", source, test.declaredSize, 4); CodeOf(err) != ErrorArtifactTooLarge {
				t.Fatalf("oversized stream code = %q, err = %v", CodeOf(err), err)
			}
			if source.read != 5 {
				t.Fatalf("source bytes read = %d, want 5", source.read)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed upload stage entries = %v, err = %v", entries, err)
			}
			artifact, err := store.stageUploadWithLimit(context.Background(), "owner", strings.NewReader("1234"), -1, 4)
			if err != nil {
				t.Fatalf("oversized upload leaked quota: %v", err)
			}
			if err := store.Remove(artifact); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStageUploadSharesOwnerAndGlobalStagedByteQuotas(t *testing.T) {
	store, err := NewStageStoreWithOptions(t.TempDir(), StageStoreOptions{
		MaxConcurrentFetches: 3, MaxOwnerConcurrentFetches: 2,
		MaxStagedBytes: 7, MaxOwnerStagedBytes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ownerA, err := store.stageUploadWithLimit(context.Background(), "owner-a", strings.NewReader("1234"), 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.stageUploadWithLimit(context.Background(), "owner-a", strings.NewReader("xx"), -1, 5); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("owner byte quota code = %q, err = %v", CodeOf(err), err)
	}
	ownerB, err := store.stageUploadWithLimit(context.Background(), "owner-b", strings.NewReader("567"), -1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.stageUploadWithLimit(context.Background(), "owner-c", strings.NewReader("x"), -1, 5); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("global byte quota code = %q, err = %v", CodeOf(err), err)
	}
	if err := store.Remove(ownerA); err != nil {
		t.Fatal(err)
	}
	replacement, err := store.stageUploadWithLimit(context.Background(), "owner-c", strings.NewReader("xx"), -1, 5)
	if err != nil {
		t.Fatalf("remove did not release upload byte quota: %v", err)
	}
	for _, artifact := range []StagedArtifact{ownerB, replacement} {
		if err := store.Remove(artifact); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStageUploadSharesActiveTransferQuotasWithFetch(t *testing.T) {
	store, err := NewStageStoreWithOptions(t.TempDir(), StageStoreOptions{
		MaxConcurrentFetches: 2, MaxOwnerConcurrentFetches: 1,
		MaxStagedBytes: 4, MaxOwnerStagedBytes: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	started := make(chan struct{}, 1)
	releaseUpload := make(chan struct{})
	type uploadOutcome struct {
		artifact StagedArtifact
		err      error
	}
	outcome := make(chan uploadOutcome, 1)
	go func() {
		artifact, err := store.stageUploadWithLimit(context.Background(), "owner-a", &blockingReader{started: started, release: releaseUpload}, 1, 2)
		outcome <- uploadOutcome{artifact: artifact, err: err}
	}()
	<-started

	if _, err := store.acquireFetch("owner-a"); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("upload did not consume owner transfer quota: code = %q, err = %v", CodeOf(err), err)
	}
	releaseFetch, err := store.acquireFetch("owner-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.stageUploadWithLimit(context.Background(), "owner-c", panicReader{}, 1, 2); CodeOf(err) != ErrorQuotaExceeded {
		t.Fatalf("fetch did not consume global transfer quota: code = %q, err = %v", CodeOf(err), err)
	}
	releaseFetch()
	close(releaseUpload)
	result := <-outcome
	if result.err != nil {
		t.Fatal(result.err)
	}
	if err := store.Remove(result.artifact); err != nil {
		t.Fatal(err)
	}

	releaseAfter, err := store.acquireFetch("owner-a")
	if err != nil {
		t.Fatalf("completed upload leaked active transfer quota: %v", err)
	}
	releaseAfter()
}

func TestStageUploadCleansAndReleasesQuotaOnCancelAndReadFailure(t *testing.T) {
	directory := t.TempDir()
	store, err := NewStageStoreWithOptions(directory, StageStoreOptions{
		MaxConcurrentFetches: 1, MaxOwnerConcurrentFetches: 1,
		MaxStagedBytes: 4, MaxOwnerStagedBytes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.stageUploadWithLimit(ctx, "owner", strings.NewReader("1234"), -1, 4); CodeOf(err) != ErrorTransport {
		t.Fatalf("cancel code = %q, err = %v", CodeOf(err), err)
	}

	readOnce := false
	failedReader := readerFunc(func(value []byte) (int, error) {
		if readOnce {
			return 0, fmt.Errorf("read failed")
		}
		readOnce = true
		copy(value, "12")
		return 2, fmt.Errorf("read failed")
	})
	if _, err := store.stageUploadWithLimit(context.Background(), "owner", failedReader, -1, 4); CodeOf(err) != ErrorTransport {
		t.Fatalf("read failure code = %q, err = %v", CodeOf(err), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed upload stage entries = %v, err = %v", entries, err)
	}

	artifact, err := store.stageUploadWithLimit(context.Background(), "owner", strings.NewReader("1234"), -1, 4)
	if err != nil {
		t.Fatalf("failed upload leaked active or byte quota: %v", err)
	}
	if err := store.Remove(artifact); err != nil {
		t.Fatal(err)
	}
}

func TestNewStageStoreRemovesOnlyOwnedOrphanArtifacts(t *testing.T) {
	directory := t.TempDir()
	orphanName := stageFilename("0123456789abcdef0123456789abcdef")
	partialName := stageFilename("abcdef0123456789abcdef0123456789")
	for name, content := range map[string]string{
		orphanName:             "orphan",
		partialName:            "",
		"keep.txt":             "user data",
		"not-a-stage.artifact": "not owned",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tamperedName := stageFilename("fedcba9876543210fedcba9876543210")
	if err := os.WriteFile(filepath.Join(directory, tamperedName), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	directoryName := stageFilename("00112233445566778899aabbccddeeff")
	if err := os.Mkdir(filepath.Join(directory, directoryName), 0o700); err != nil {
		t.Fatal(err)
	}

	store, err := NewStageStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for _, name := range []string{orphanName, partialName} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned orphan %q was not removed: %v", name, err)
		}
	}
	for _, name := range []string{"keep.txt", "not-a-stage.artifact", tamperedName, directoryName} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("non-owned entry %q was removed: %v", name, err)
		}
	}
}
