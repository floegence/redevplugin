package resourceio

import (
	"errors"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var ErrInvalidURI = errors.New("invalid redevfs URI")

type URI struct {
	MountID string
	Path    string
}

func ParseURI(raw string) (URI, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "redevfs" || !validMountID(parsed.Host) || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return URI{}, ErrInvalidURI
	}
	escapedPath := parsed.EscapedPath()
	if !strings.HasPrefix(parsed.Path, "/") || strings.Contains(strings.ToLower(escapedPath), "%2f") || strings.Contains(strings.ToLower(escapedPath), "%5c") {
		return URI{}, ErrInvalidURI
	}
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil || strings.ContainsRune(decoded, '\x00') || strings.Contains(decoded, "\\") {
		return URI{}, ErrInvalidURI
	}
	decoded = norm.NFC.String(decoded)
	path := strings.TrimPrefix(decoded, "/")
	if path == "" {
		return URI{MountID: parsed.Host, Path: "."}, nil
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return URI{}, ErrInvalidURI
		}
	}
	return URI{MountID: parsed.Host, Path: strings.Join(parts, "/")}, nil
}

func (uri URI) String() string {
	if !validMountID(uri.MountID) || uri.Path == "" {
		return ""
	}
	if uri.Path == "." {
		return "redevfs://" + uri.MountID + "/"
	}
	parts := strings.Split(uri.Path, "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\\x00") {
			return ""
		}
		parts[index] = url.PathEscape(norm.NFC.String(part))
	}
	return "redevfs://" + uri.MountID + "/" + strings.Join(parts, "/")
}

func validMountID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char > unicode.MaxASCII || !(unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
