//go:build linux

package resourceio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const inotifyEventHeaderBytes = 16

type inotifyWatch struct {
	mu        sync.Mutex
	closed    atomic.Bool
	fd        int
	wakeRead  int
	wakeWrite int
	target    *os.File
	base      URI
	sequence  uint64
	pending   []WatchEvent
}

func openWatchImplementation(target *os.File, uri URI) (watchImplementation, error) {
	if target == nil || uri.String() == "" {
		return nil, ErrInvalidURI
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	wake := []int{0, 0}
	if err := unix.Pipe2(wake, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	watch := &inotifyWatch{fd: fd, wakeRead: wake[0], wakeWrite: wake[1], target: target, base: uri}
	mask := uint32(unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_DELETE_SELF | unix.IN_MODIFY | unix.IN_MOVE_SELF | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_Q_OVERFLOW)
	if _, err := unix.InotifyAddWatch(fd, fmt.Sprintf("/proc/self/fd/%d", target.Fd()), mask); err != nil {
		_ = watch.closeDescriptors()
		return nil, err
	}
	return watch, nil
}

func (watch *inotifyWatch) Next(ctx context.Context, timeout time.Duration) (WatchEvent, error) {
	if watch == nil {
		return WatchEvent{}, ErrResourceClosed
	}
	watch.mu.Lock()
	defer watch.mu.Unlock()
	if watch.closed.Load() {
		return WatchEvent{}, ErrResourceClosed
	}
	if len(watch.pending) > 0 {
		return watch.takePending(), nil
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return WatchEvent{}, err
		}
		if watch.closed.Load() {
			return WatchEvent{}, ErrResourceClosed
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return WatchEvent{}, context.DeadlineExceeded
		}
		pollTimeout := min(remaining, 100*time.Millisecond)
		pollMillis := int((pollTimeout + time.Millisecond - 1) / time.Millisecond)
		pollFDs := []unix.PollFd{{Fd: int32(watch.fd), Events: unix.POLLIN}, {Fd: int32(watch.wakeRead), Events: unix.POLLIN}}
		count, err := unix.Poll(pollFDs, pollMillis)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return WatchEvent{}, err
		}
		if watch.closed.Load() || pollFDs[1].Revents != 0 {
			return WatchEvent{}, ErrResourceClosed
		}
		if count == 0 || pollFDs[0].Revents&unix.POLLIN == 0 {
			continue
		}
		buffer := make([]byte, 64<<10)
		n, err := unix.Read(watch.fd, buffer)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return WatchEvent{}, err
		}
		watch.decode(buffer[:n])
		if len(watch.pending) > 0 {
			return watch.takePending(), nil
		}
	}
}

func (watch *inotifyWatch) decode(raw []byte) {
	movedFrom := make(map[uint32]string)
	for offset := 0; offset+inotifyEventHeaderBytes <= len(raw); {
		mask := binary.NativeEndian.Uint32(raw[offset+4 : offset+8])
		cookie := binary.NativeEndian.Uint32(raw[offset+8 : offset+12])
		nameLength := int(binary.NativeEndian.Uint32(raw[offset+12 : offset+16]))
		next := offset + inotifyEventHeaderBytes + nameLength
		if nameLength < 0 || next > len(raw) {
			watch.append(WatchKindOverflow, watch.base.String(), "")
			return
		}
		name := strings.TrimRight(string(raw[offset+inotifyEventHeaderBytes:next]), "\x00")
		uri := watch.eventURI(name)
		switch {
		case mask&unix.IN_Q_OVERFLOW != 0:
			watch.append(WatchKindOverflow, watch.base.String(), "")
		case mask&unix.IN_IGNORED != 0:
		case mask&unix.IN_MOVED_FROM != 0:
			movedFrom[cookie] = uri
		case mask&unix.IN_MOVED_TO != 0:
			if previous := movedFrom[cookie]; previous != "" {
				watch.append(WatchKindRename, uri, previous)
				delete(movedFrom, cookie)
			} else {
				watch.append(WatchKindCreate, uri, "")
			}
		case mask&(unix.IN_DELETE|unix.IN_DELETE_SELF) != 0:
			watch.append(WatchKindDelete, uri, "")
		case mask&unix.IN_CREATE != 0:
			watch.append(WatchKindCreate, uri, "")
		case mask&(unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_CLOSE_WRITE) != 0:
			watch.append(WatchKindChange, uri, "")
		case mask&unix.IN_MOVE_SELF != 0:
			watch.append(WatchKindRename, uri, "")
		}
		offset = next
	}
	for _, previous := range movedFrom {
		watch.append(WatchKindDelete, previous, "")
	}
}

func (watch *inotifyWatch) eventURI(name string) string {
	if name == "" {
		return watch.base.String()
	}
	if !utf8.ValidString(name) || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return watch.base.String()
	}
	path := name
	if watch.base.Path != "." {
		path = watch.base.Path + "/" + name
	}
	return (URI{MountID: watch.base.MountID, Path: path}).String()
}

func (watch *inotifyWatch) append(kind WatchKind, uri, previous string) {
	watch.sequence++
	watch.pending = append(watch.pending, WatchEvent{Sequence: watch.sequence, Kind: kind, URI: uri, PreviousURI: previous})
}

func (watch *inotifyWatch) takePending() WatchEvent {
	event := watch.pending[0]
	watch.pending = watch.pending[1:]
	return event
}

func (watch *inotifyWatch) Close() error {
	if watch == nil || !watch.closed.CompareAndSwap(false, true) {
		return nil
	}
	_, _ = unix.Write(watch.wakeWrite, []byte{1})
	watch.mu.Lock()
	defer watch.mu.Unlock()
	return watch.closeDescriptors()
}

func (watch *inotifyWatch) closeDescriptors() error {
	var joined error
	for _, fd := range []int{watch.fd, watch.wakeRead, watch.wakeWrite} {
		if fd >= 0 {
			joined = errors.Join(joined, unix.Close(fd))
		}
	}
	watch.fd, watch.wakeRead, watch.wakeWrite = -1, -1, -1
	if watch.target != nil {
		joined = errors.Join(joined, watch.target.Close())
		watch.target = nil
	}
	return joined
}

var _ io.Closer = (*inotifyWatch)(nil)
