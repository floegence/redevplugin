package plugindata

import (
	"bytes"
	"context"
	"errors"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"io"
	"testing"
)

type failingFileReader struct{ sent bool }

func (r *failingFileReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.ErrUnexpectedEOF
	}
	r.sent = true
	return copy(p, "partial"), nil
}
func TestPrivateFileStreamAtomicityAndBounds(t *testing.T) {
	s, _, shape := newInternalStore(t)
	shape.Namespaces[0].QuotaBytes = 16 << 20
	ctx := internalTestContext()
	installInternalStore(t, s, ctx, "plugini_test", shape)
	req := storage.FileStreamWriteRequest{FileWriteRequest: storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "draft.bin"}, MaxBytes: 8 << 20}
	data := bytes.Repeat([]byte("a"), 2<<20)
	if _, err := s.WriteFileStream(ctx, req, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteFileStream(ctx, req, &failingFileReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial input: %v", err)
	}
	var output bytes.Buffer
	read := storage.FileReadRequest{PluginInstanceID: req.PluginInstanceID, ResourceScope: req.ResourceScope, StoreID: req.StoreID, Path: req.Path, MaxBytes: 8 << 20}
	if _, err := s.ReadFileStream(ctx, read, &output); err != nil || !bytes.Equal(output.Bytes(), data) {
		t.Fatalf("rollback/read: %v", err)
	}
	req.BeforeCommit = func(context.Context) (func(), error) { return nil, context.Canceled }
	if _, err := s.WriteFileStream(ctx, req, bytes.NewBufferString("denied")); !errors.Is(err, context.Canceled) {
		t.Fatalf("commit fence: %v", err)
	}
	result, err := s.ReadFile(ctx, read)
	if err != nil || !bytes.Equal(result.Data, data) {
		t.Fatalf("authorization rollback: %v", err)
	}
	read.MaxBytes = 1
	if _, err := s.ReadFile(ctx, read); !errors.Is(err, storage.ErrFileTooLarge) {
		t.Fatalf("bounded read: %v", err)
	}
}

func TestPrivateFileStreamStagingBudgetIsSharedAndReleased(t *testing.T) {
	s := &FileStore{}
	first := &namespaceStageWriter{store: s, key: "owner/files", limit: 8, writer: io.Discard}
	second := &namespaceStageWriter{store: s, key: "owner/files", limit: 8, writer: io.Discard}
	other := &namespaceStageWriter{store: s, key: "other/files", limit: 8, writer: io.Discard}
	if _, err := first.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("6789")); !errors.Is(err, storage.ErrQuotaExceeded) {
		t.Fatalf("shared limit: %v", err)
	}
	if _, err := other.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	first.release()
	if _, err := second.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	second.release()
	other.release()
	if len(s.streamBytes) != 0 {
		t.Fatal("staging reservation leaked")
	}
}

func TestChunkedFilesSurviveExportAndRestore(t *testing.T) {
	s, _, shape := newInternalStore(t)
	shape.Namespaces[0].QuotaBytes = 8 << 20
	ctx := internalTestContext()
	installInternalStore(t, s, ctx, "plugini_test", shape)
	data := bytes.Repeat([]byte("snapshot"), 16384)
	req := storage.FileStreamWriteRequest{FileWriteRequest: storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "document"}, MaxBytes: 2 << 20}
	if _, err := s.WriteFileStream(ctx, req, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	exported, err := s.Export(ctx, ExportRequest{PluginInstanceID: "plugini_test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.WriteFileStream(ctx, req, bytes.NewBufferString("changed")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Import(ctx, ImportRequest{PluginInstanceID: "plugini_test", ObjectID: exported.ObjectID, ExpectedShape: shape, ExpectedManagementRevision: 2}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err = s.ReadFileStream(ctx, storage.FileReadRequest{PluginInstanceID: req.PluginInstanceID, ResourceScope: req.ResourceScope, StoreID: req.StoreID, Path: req.Path, MaxBytes: 2 << 20}, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("restored chunked file differs")
	}
}
