package plugindata

import (
	"bytes"
	"fmt"
	"github.com/floegence/redevplugin/v3/pkg/storage"
	"io"
	"testing"
)

// Measure allocations and throughput separately from authorization and browser IO.
// Streams intentionally stage snapshots on disk; these are not zero-copy claims.
func BenchmarkAuthorPrivateFileStream(b *testing.B) {
	for _, size := range []int{1 << 20, 16 << 20} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s, _, shape := newInternalStore(b)
			shape.Namespaces[0].QuotaBytes = 64 << 20
			ctx := internalTestContext()
			installInternalStore(b, s, ctx, "plugini_test", shape)
			data := bytes.Repeat([]byte("x"), size)
			write := storage.FileStreamWriteRequest{FileWriteRequest: storage.FileWriteRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "file.bin"}, MaxBytes: 32 << 20}
			if _, err := s.WriteFileStream(ctx, write, bytes.NewReader(data)); err != nil {
				b.Fatal(err)
			}
			b.Run("read", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := s.ReadFileStream(ctx, storage.FileReadRequest{PluginInstanceID: "plugini_test", ResourceScope: internalUserScope(), StoreID: "files", Path: "file.bin", MaxBytes: 32 << 20}, io.Discard); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("write", func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := s.WriteFileStream(ctx, write, bytes.NewReader(data)); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
