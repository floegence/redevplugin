package capabilitycontract

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ReadBundle reads the exact file set named by a validated pin without
// following links or accepting files with additional hard links.
func ReadBundle(root string, pin Pin) (Bundle, error) {
	if err := ValidatePin(pin); err != nil {
		return Bundle{}, err
	}
	files := make(map[string][]byte, 6)
	for ref := range pinRefs(pin) {
		content, err := readArtifactFile(root, ref)
		if err != nil {
			return Bundle{}, err
		}
		files[ref] = content
	}
	return Bundle{Pin: pin, Files: files}, nil
}

func readArtifactFile(root, ref string) ([]byte, error) {
	if err := ValidateArtifactRef(ref); err != nil {
		return nil, err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	rootHandle, err := os.OpenRoot(rootAbs)
	if err != nil {
		return nil, err
	}
	defer rootHandle.Close()
	relative := filepath.FromSlash(ref)
	segments := strings.Split(relative, string(filepath.Separator))
	current := ""
	var info os.FileInfo
	for index, segment := range segments {
		current = filepath.Join(current, segment)
		info, err = rootHandle.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("host capability artifact must be a regular unlinked file")
		}
		if index < len(segments)-1 && !info.IsDir() {
			return nil, errors.New("host capability artifact parent must be a directory")
		}
	}
	if !regularUnlinkedFile(info) {
		return nil, errors.New("host capability artifact must be a regular unlinked file")
	}
	file, err := rootHandle.Open(relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) || !regularUnlinkedFile(openedInfo) {
		return nil, errors.New("host capability artifact changed while opening")
	}
	if openedInfo.Size() < 0 || openedInfo.Size() > MaxArtifactFileBytes {
		return nil, errors.New("host capability artifact exceeds the per-file byte budget")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxArtifactFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != openedInfo.Size() || int64(len(content)) > MaxArtifactFileBytes {
		return nil, errors.New("host capability artifact changed size while reading")
	}
	return content, nil
}

func regularUnlinkedFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
