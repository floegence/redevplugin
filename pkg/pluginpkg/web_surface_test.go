package pluginpkg

import "testing"

func TestSurfaceAcceptsNativeWebApplication(t *testing.T) {
	entry := []byte(`<!doctype html><html><head><link rel="stylesheet" href="/assets/app.css"></head><body><div id="app" style="display:grid"></div><script type="module" src="/assets/app.js"></script></body></html>`)
	files := map[string][]byte{
		"web/index.html":       entry,
		"web/assets/app.css":   []byte(`@font-face{font-family:app;src:url('./font.woff2')}#app{display:grid;grid-template-columns:1fr 2fr}`),
		"web/assets/app.js":    []byte(`const chunk=await import('./chunk.js');document.querySelector('#app').textContent=chunk.value;new Worker(new URL('./worker.js',import.meta.url),{type:'module'});`),
		"web/assets/chunk.js":  []byte(`export const value='native application';`),
		"web/assets/worker.js": []byte(`self.postMessage('ready');`),
	}
	if err := validateSurfaceHTMLAsset("web/index.html", entry, files); err != nil {
		t.Fatalf("ordinary Web application rejected: %v", err)
	}
}

func TestSurfaceRejectsRemovedWorkerUIFormat(t *testing.T) {
	entry := []byte(`<html><body><script type="text/redevplugin-worker" src="app.js"></script></body></html>`)
	files := map[string][]byte{"web/index.html": entry, "web/app.js": []byte(`console.log('obsolete UI')`)}
	if err := validateSurfaceHTMLAsset("web/index.html", entry, files); err == nil {
		t.Fatal("removed worker UI format was accepted")
	}
}
