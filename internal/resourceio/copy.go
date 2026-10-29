package resourceio

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/floegence/redevplugin/v3/pkg/mutation"
)

func copyBetweenMounts(ctx context.Context, sourceMount, destinationMount Mount, from, to URI, overwrite bool) (retErr error) {
	changed := false
	defer func() {
		if changed && retErr != nil {
			retErr = mutation.Unknown(retErr)
		}
	}()
	source, err := sourceMount.OpenFile(from, OpenOptions{Read: true})
	if err != nil {
		return err
	}
	defer source.Close()
	if selected, ok := source.(*selectedAuthorizedFile); ok {
		selected.mount.ctx = ctx
	}
	info, err := source.Stat()
	if err != nil {
		return err
	}
	options := OpenOptions{Write: true, Create: overwrite, CreateNew: !overwrite, Mode: info.Mode().Perm()}
	if destinationMount.selected != nil && to.Path == "." {
		if !overwrite {
			return os.ErrExist
		}
		options.Create = false
		options.CreateNew = false
	}
	destination, err := destinationMount.OpenFile(to, options)
	if err != nil {
		return err
	}
	defer destination.Close()
	if selected, ok := destination.(*selectedAuthorizedFile); ok {
		selected.mount.ctx = ctx
	}
	changed = options.Create || options.CreateNew
	destinationInfo, err := destination.Stat()
	if err != nil {
		return err
	}
	if os.SameFile(info, destinationInfo) {
		return ErrInvalidOptions
	}
	// Validate both ends before the first destructive operation. Subsequent
	// bounded reads and writes retain their own revocation and cancellation checks.
	if _, err := source.Stat(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if overwrite {
		changed = true
		if err := destination.Truncate(0); err != nil {
			return err
		}
	}
	buffer := make([]byte, MaxIOChunkBytes)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			changed = true
			written, err := destination.Write(buffer[:n])
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return destination.Sync()
}
