package websecurity

import (
	"context"
	"testing"
)

func TestRequestScopeValidRequiresSessionAndChannel(t *testing.T) {
	if (RequestScope{}).Valid() {
		t.Fatal("empty request scope must be invalid")
	}
	if (RequestScope{OwnerSessionHash: "session_hash"}).Valid() {
		t.Fatal("request scope without channel must be invalid")
	}
	if !(RequestScope{OwnerSessionHash: "session_hash", SessionChannelIDHash: "channel_hash"}).Valid() {
		t.Fatal("request scope with session and channel must be valid")
	}
}

func TestRequestContextRoundTrip(t *testing.T) {
	want := RequestContext{
		Origin: "https://env.example",
		Route:  "/_redevplugin/api/plugins/catalog",
		Method: "GET",
		Scope: RequestScope{
			OwnerSessionHash:     "session_hash",
			OwnerUserHash:        "user_hash",
			SessionChannelIDHash: "channel_hash",
		},
	}
	got, ok := RequestContextFromContext(WithRequestContext(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("request context = %#v, %v, want %#v, true", got, ok, want)
	}
}
