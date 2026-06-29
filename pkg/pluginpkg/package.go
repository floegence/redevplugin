package pluginpkg

import (
	"context"
	"io"

	"github.com/floegence/redevplugin/pkg/manifest"
)

type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Package struct {
	Manifest          manifest.Manifest `json:"manifest"`
	PackageHash       string            `json:"package_hash"`
	CanonicalManifest string            `json:"canonical_manifest"`
	Entries           []Entry           `json:"entries"`
}

type ReadOptions struct {
	MaxUncompressedBytes int64 `json:"max_uncompressed_bytes"`
	MaxFiles             int   `json:"max_files"`
	MaxEntryBytes        int64 `json:"max_entry_bytes"`
}

type Reader interface {
	ReadPackage(ctx context.Context, r io.Reader, opts ReadOptions) (Package, error)
}

type Writer interface {
	WritePackage(ctx context.Context, w io.Writer, pkg Package) error
}
