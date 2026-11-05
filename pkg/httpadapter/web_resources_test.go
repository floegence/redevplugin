package httpadapter

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/v3/pkg/host"
)

func TestWebResourcesRejectCrossOriginAndExecutableFetches(t *testing.T) {
	for _, change := range []func(*map[string]string){
		func(h *map[string]string) { (*h)["Origin"] = "https://other.example" },
		func(h *map[string]string) { (*h)["Sec-Fetch-Site"] = "same-site" },
		func(h *map[string]string) { (*h)["Sec-Fetch-Dest"] = "script" },
		func(h *map[string]string) { (*h)["Sec-Fetch-Mode"] = "no-cors" },
	} {
		headers := map[string]string{"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Content-Type": "application/json"}
		change(&headers)
		r := httptest.NewRequest("POST", "https://app.example/_redevplugin_web/resource", strings.NewReader(`{"resource":"describe","arguments":{}}`))
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		serveWebResource(nil, w, r, host.WebSurfaceRequest{Origin: "https://app.example"})
		if w.Code != 403 {
			t.Fatalf("status %d", w.Code)
		}
	}
}
