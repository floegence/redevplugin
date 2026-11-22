package pluginpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"

	"github.com/floegence/redevplugin/v3/pkg/agentconversation"
	"github.com/floegence/redevplugin/v3/pkg/manifest"
)

func checkArchiveDirectory(input io.ReaderAt, size int64, limits ReadLimits) error {
	invalid := func() error {
		return validationErrorf(ValidationCodePackageInvalid, "zip_invalid", "", "", "invalid archive directory")
	}
	if size < 22 {
		return invalid()
	}
	tail := make([]byte, min(size, 22+65535))
	if _, err := input.ReadAt(tail, size-int64(len(tail))); err != nil {
		return invalid()
	}
	var end []byte
	for index := len(tail) - 22; index >= 0; index-- {
		if bytes.Equal(tail[index:index+4], []byte{'P', 'K', 5, 6}) && int(binary.LittleEndian.Uint16(tail[index+20:])) == len(tail)-index-22 {
			end = tail[index:]
			break
		}
	}
	if end == nil {
		return invalid()
	}
	le := binary.LittleEndian
	count := uint64(le.Uint16(end[10:]))
	length, offset := uint64(le.Uint32(end[12:])), uint64(le.Uint32(end[16:]))
	endPosition := size - int64(len(end))
	if count == math.MaxUint16 || length == math.MaxUint32 || offset == math.MaxUint32 {
		var locator [20]byte
		if endPosition < 76 {
			return invalid()
		}
		if _, err := input.ReadAt(locator[:], endPosition-20); err != nil || le.Uint32(locator[:]) != 0x07064b50 || le.Uint32(locator[4:]) != 0 || le.Uint32(locator[16:]) != 1 {
			return invalid()
		}
		zip64 := le.Uint64(locator[8:])
		if zip64 > uint64(endPosition-76) {
			return invalid()
		}
		var record [56]byte
		if _, err := input.ReadAt(record[:], int64(zip64)); err != nil || le.Uint32(record[:]) != 0x06064b50 || le.Uint64(record[4:]) != uint64(endPosition-20)-zip64-12 {
			return invalid()
		}
		count, length, offset = le.Uint64(record[32:]), le.Uint64(record[40:]), le.Uint64(record[48:])
		endPosition = int64(zip64)
	}
	if count > uint64(limits.maxFiles) || length > uint64(maxFileAssetManifestBytes) {
		return validationErrorf(ValidationCodePackageTooLarge, "file_count", "", "", "archive directory exceeds limits")
	}
	if offset > uint64(endPosition) || length != uint64(endPosition)-offset {
		return invalid()
	}
	for index := uint64(0); index < count; index++ {
		var header [46]byte
		if offset > uint64(endPosition) || uint64(endPosition)-offset < uint64(len(header)) {
			return invalid()
		}
		if _, err := input.ReadAt(header[:], int64(offset)); err != nil || le.Uint32(header[:]) != 0x02014b50 {
			return invalid()
		}
		name := le.Uint16(header[28:])
		if int(name) > limits.maxPathBytes {
			return invalid()
		}
		offset += uint64(len(header)) + uint64(name) + uint64(le.Uint16(header[30:])) + uint64(le.Uint16(header[32:]))
	}
	if offset != uint64(endPosition) {
		return invalid()
	}
	return nil
}

func fullValidationPaths(archive *zip.Reader) (map[string]bool, error) {
	file, err := archive.Open("manifest.json")
	if err != nil {
		return nil, validationErrorf(ValidationCodeManifestInvalid, "manifest_missing", "manifest.json", "", "manifest.json is required")
	}
	defer file.Close()
	decoded, _, err := manifest.DecodeCanonical(io.LimitReader(file, DefaultReadLimits().maxEntryBytes+1))
	if err != nil {
		return nil, manifestDecodeValidationError(err)
	}
	paths := map[string]bool{"manifest.json": true, agentconversation.RolesPath: true}
	for _, worker := range decoded.Workers {
		paths[worker.Artifact] = true
	}
	for _, surface := range decoded.Surfaces {
		paths[surface.Entry] = true
	}
	if icon := decoded.Presentation.Icon; icon != nil {
		paths[icon.Path] = true
	}
	return paths, nil
}

func streamZipEntry(ctx context.Context, file *zip.File, destination io.Writer) (Entry, []byte, error) {
	if file.UncompressedSize64 >= math.MaxInt64 {
		return Entry{}, nil, errZipEntrySizeMismatch
	}
	reader, err := file.Open()
	if err != nil {
		return Entry{}, nil, err
	}
	defer reader.Close()
	size := int64(file.UncompressedSize64)
	hash := sha256.New()
	body := io.LimitReader(reader, size+1)
	prefix := make([]byte, min(512, size))
	if _, err := io.ReadFull(body, prefix); err != nil {
		return Entry{}, nil, err
	}
	out := io.MultiWriter(destination, hash)
	if _, err := out.Write(prefix); err != nil {
		return Entry{}, nil, err
	}
	count, err := io.Copy(out, contextPackageReader{ctx, body})
	if err != nil || count != size-int64(len(prefix)) {
		return Entry{}, nil, errors.Join(errZipEntrySizeMismatch, err)
	}
	return Entry{Path: file.Name, Size: size, Mode: "0644", SHA256: "sha256:" + hex.EncodeToString(hash.Sum(nil)), ContentType: contentType(file.Name, prefix)}, prefix, nil
}

type contextPackageReader struct {
	ctx    context.Context
	reader io.Reader
}

func (source contextPackageReader) Read(dst []byte) (int, error) {
	if err := source.ctx.Err(); err != nil {
		return 0, err
	}
	return source.reader.Read(dst)
}
