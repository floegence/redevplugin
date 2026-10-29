package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

// UnmarshalJSON requires the routing decision to be explicit in signed input.
func (web *SurfaceWebSpec) UnmarshalJSON(raw []byte) error {
	var value struct {
		Network []NetworkBrokerAccessSpec `json:"network,omitempty"`
		Root    *string                   `json:"root"`
		SPA     *bool                     `json:"spa"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if value.Root == nil || value.SPA == nil {
		return errors.New("web root and SPA routing policy are required")
	}
	*web = SurfaceWebSpec{Root: *value.Root, SPA: *value.SPA, Network: value.Network}
	return nil
}

func validateSurfaceWeb(surface SurfaceSpec) error {
	root := surface.Web.Root
	if root == "" || utf8.RuneCountInString(root) > 512 || root != path.Clean(root) || strings.HasPrefix(root, "/") || strings.ContainsAny(root, "\\?#:%\x00\r\n\t") {
		return errors.New("root must be a canonical package directory")
	}
	for _, part := range strings.Split(root, "/") {
		if part == "" || strings.HasPrefix(part, ".") {
			return errors.New("root contains a forbidden path segment")
		}
	}
	if surface.Entry != path.Clean(surface.Entry) || !strings.HasPrefix(surface.Entry, root+"/") || strings.ContainsAny(surface.Entry, "\\?#:%\x00\r\n\t") {
		return errors.New("entry must be a canonical file inside the Web root")
	}
	ext := strings.ToLower(path.Ext(surface.Entry))
	if ext != ".html" && ext != ".htm" {
		return errors.New("entry must be HTML")
	}
	return nil
}
