package resourceio

import "testing"

func TestParseURICanonicalizesAndRejectsEscapes(t *testing.T) {
	uri, err := ParseURI("redevfs://workspace/src/main.go")
	if err != nil || uri.MountID != "workspace" || uri.Path != "src/main.go" {
		t.Fatalf("ParseURI() = %#v, %v", uri, err)
	}
	if got := uri.String(); got != "redevfs://workspace/src/main.go" {
		t.Fatalf("URI.String() = %q", got)
	}
	encoded, err := ParseURI("redevfs://workspace/space%20name/%23notes.txt")
	if err != nil || encoded.Path != "space name/#notes.txt" || encoded.String() != "redevfs://workspace/space%20name/%23notes.txt" {
		t.Fatalf("encoded URI round trip = %#v, %v", encoded, err)
	}
	root, err := ParseURI("redevfs://workspace/")
	if err != nil || root.Path != "." || root.String() != "redevfs://workspace/" {
		t.Fatalf("root URI round trip = %#v, %v", root, err)
	}
	for _, raw := range []string{
		"redevfs://workspace/../secret",
		"redevfs://workspace/a%2fb",
		"redevfs://workspace/a\\b",
		"redevfs://workspace/a//b",
		"redevfs://workspace/%zz",
		"redevfs://workspace:80/file",
		"redevfs://work%2fspace/file",
	} {
		if _, err := ParseURI(raw); err == nil {
			t.Fatalf("ParseURI(%q) unexpectedly succeeded", raw)
		}
	}
}
