package externalsource

import "testing"

func TestParseDirectPackageURLCanonicalizesSafeLocator(t *testing.T) {
	locator, err := ParseDirectPackageURL("https://EXAMPLE.com/plugins/demo.redevplugin")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := locator.DisplayURL(), "https://example.com:443/plugins/demo.redevplugin"; got != want {
		t.Fatalf("DisplayURL() = %q, want %q", got, want)
	}
	if got, want := locator.Origin(), (Origin{Scheme: "https", Host: "example.com", Port: 443}); got != want {
		t.Fatalf("Origin() = %#v, want %#v", got, want)
	}
}

func TestParseDirectPackageURLRejectsUnsafeLocators(t *testing.T) {
	tests := []string{
		"http://example.com/plugin.redevplugin",
		"file:///tmp/plugin.redevplugin",
		"https://user:secret@example.com/plugin.redevplugin",
		"https://example.com/plugin.redevplugin?token=secret",
		"https://example.com/plugin.redevplugin#fragment",
		"https://example.com/a%2fb.redevplugin",
		"https://example.com/a%5cb.redevplugin",
		"https://example.com/a%00b.redevplugin",
		"https://example.com/a/../b.redevplugin",
		"https://example.com//b.redevplugin",
		"https://[fe80::1%25en0]/plugin.redevplugin",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseDirectPackageURL(raw)
			if CodeOf(err) != ErrorInvalidURL {
				t.Fatalf("CodeOf(ParseDirectPackageURL()) = %q, want %q (err=%v)", CodeOf(err), ErrorInvalidURL, err)
			}
		})
	}
}

func TestPackageURLDisplayRedactsAllowedQuery(t *testing.T) {
	locator, err := parsePackageURL("https://example.com/plugin.redevplugin?token=secret", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := locator.DisplayURL(); got != "https://example.com:443/plugin.redevplugin" {
		t.Fatalf("DisplayURL() = %q", got)
	}
	if got := locator.requestURL().RawQuery; got != "token=secret" {
		t.Fatalf("request query = %q", got)
	}
}
