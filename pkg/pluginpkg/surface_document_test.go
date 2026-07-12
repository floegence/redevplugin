package pluginpkg

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildOpaqueSurfaceDocumentBuildsOneWorkerAndLazyAssetBindings(t *testing.T) {
	assets := surfaceTestAssets(t, map[string][]byte{
		"ui/index.html": []byte(`<!doctype html>
<html lang="en" dir="ltr">
  <head>
    <title>Containers</title>
    <link rel="stylesheet" href="assets/app.css">
	  </head>
	  <body>
	    <main class="surface" data-redevplugin-action="refresh">
	      <img alt="Containers" src="assets/icon.png">
	      <h1>Containers</h1>
    </main>
    <script type="text/redevplugin-worker" src="assets/app.js"></script>
  </body>
</html>`),
		"ui/assets/app.css":          []byte(`body { color: rgb(20 24 28); background-image: url("background.png"); }`),
		"ui/assets/app.js":           []byte(`const bridge = new PluginBridgeClient(); void bridge.ready();`),
		"ui/assets/icon.png":         {0x89, 'P', 'N', 'G'},
		"ui/assets/background.png":   {0x89, 'P', 'N', 'G', 1},
		"ui/assets/unreferenced.png": {0x89, 'P', 'N', 'G', 2},
	})
	readPaths := []string{}
	document, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
		readPaths = append(readPaths, assetPath)
		asset, ok := assets[assetPath]
		if !ok {
			return Asset{}, fmt.Errorf("missing asset %s", assetPath)
		}
		return asset, nil
	})
	if err != nil {
		t.Fatalf("BuildOpaqueSurfaceDocument() error = %v", err)
	}
	if document.SchemaVersion != OpaqueSurfaceDocumentSchemaVersion || document.EntryPath != "ui/index.html" || document.EntrySHA256 != assets["ui/index.html"].Entry.SHA256 {
		t.Fatalf("document identity mismatch: %#v", document)
	}
	if document.Title != "Containers" || document.Language != "en" || document.Direction != "ltr" {
		t.Fatalf("document metadata mismatch: %#v", document)
	}
	if document.Worker.Path != "ui/assets/app.js" || document.Worker.Type != OpaqueSurfaceWorkerClassic || document.Worker.SHA256 != assets["ui/assets/app.js"].Entry.SHA256 {
		t.Fatalf("worker mismatch: %#v", document.Worker)
	}
	if len(document.Styles) != 1 || document.Styles[0].SHA256 != assets["ui/assets/app.css"].Entry.SHA256 {
		t.Fatalf("styles mismatch: %#v", document.Styles)
	}
	if strings.Contains(document.BodyHTML, "onclick") || strings.Contains(document.BodyHTML, "style=") || strings.Contains(document.BodyHTML, "src=") || strings.Contains(document.BodyHTML, "data:image") {
		t.Fatalf("body HTML retained an executable or eager asset attribute: %s", document.BodyHTML)
	}
	if !strings.Contains(document.BodyHTML, "data-redevplugin-asset-binding=") || !strings.Contains(document.BodyHTML, `data-redevplugin-asset-attr="src"`) {
		t.Fatalf("body HTML missing lazy asset binding: %s", document.BodyHTML)
	}
	if len(document.Assets) != 2 {
		t.Fatalf("asset bindings = %#v, want icon and background only", document.Assets)
	}
	byPath := map[string]OpaqueSurfaceAsset{}
	for _, asset := range document.Assets {
		byPath[asset.Path] = asset
		if !strings.HasPrefix(asset.BindingID, "asset_") || asset.SHA256 != assets[asset.Path].Entry.SHA256 {
			t.Fatalf("invalid asset binding: %#v", asset)
		}
	}
	background := byPath["ui/assets/background.png"]
	if background.BindingID == "" || !strings.Contains(document.Styles[0].Content, "var(--redevplugin-asset-"+background.BindingID+")") {
		t.Fatalf("stylesheet did not use the lazy CSS asset binding: %s", document.Styles[0].Content)
	}
	if strings.Contains(strings.Join(readPaths, "\n"), "unreferenced.png") {
		t.Fatalf("unreferenced package asset was read: %#v", readPaths)
	}
	wantCritical := int64(len(assets["ui/index.html"].Content) + len(document.Styles[0].Content) + len(document.Worker.Content))
	if document.CriticalBytes != wantCritical {
		t.Fatalf("critical bytes = %d, want %d", document.CriticalBytes, wantCritical)
	}
}

func TestBuildOpaqueSurfaceDocumentBoundsLazyAssetResources(t *testing.T) {
	t.Run("asset count", func(t *testing.T) {
		files := map[string][]byte{"ui/app.js": []byte("void 0")}
		var body strings.Builder
		body.WriteString(`<body>`)
		for i := 0; i < 129; i++ {
			assetPath := fmt.Sprintf("ui/asset-%03d.png", i)
			files[assetPath] = []byte{byte(i)}
			fmt.Fprintf(&body, `<img alt="" src="asset-%03d.png">`, i)
		}
		body.WriteString(`<script type="text/redevplugin-worker" src="app.js"></script></body>`)
		files["ui/index.html"] = []byte(body.String())
		assets := surfaceTestAssets(t, files)

		_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
			return assets[assetPath], nil
		})
		if err == nil || !strings.Contains(err.Error(), "lazy asset count exceeds 128") {
			t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want lazy asset count limit", err)
		}
	})

	t.Run("cumulative bytes", func(t *testing.T) {
		files := map[string][]byte{
			"ui/index.html": []byte(`<body><img alt="" src="large.bin"><script type="text/redevplugin-worker" src="app.js"></script></body>`),
			"ui/app.js":     []byte("void 0"),
			"ui/large.bin":  make([]byte, (32<<20)+1),
		}
		assets := surfaceTestAssets(t, files)
		_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
			return assets[assetPath], nil
		})
		if err == nil || !strings.Contains(err.Error(), "lazy asset bytes exceed 33554432") {
			t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want lazy asset byte limit", err)
		}
	})
}

func TestBuildOpaqueSurfaceDocumentRejectsUnsafeWorkerAndDocumentShapes(t *testing.T) {
	tests := []struct {
		name   string
		html   string
		script string
		style  string
		want   string
	}{
		{name: "missing worker type", html: `<body><script src="app.js"></script></body>`, script: `void 0`, want: "type=text/redevplugin-worker"},
		{name: "module script", html: `<body><script type="module" src="app.js"></script></body>`, script: `void 0`, want: "type=text/redevplugin-worker"},
		{name: "inline script", html: `<body><script type="text/redevplugin-worker">alert(1)</script></body>`, want: "external bundled worker"},
		{name: "missing worker", html: `<body><main>ready</main></body>`, want: "exactly one bundled worker"},
		{name: "multiple workers", html: `<body><script type="text/redevplugin-worker" src="app.js"></script><script type="text/redevplugin-worker" src="other.js"></script></body>`, script: `void 0`, want: "exactly one bundled worker"},
		{name: "embedded frame", html: `<body><iframe src="child.html"></iframe><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: "embedded browsing context"},
		{name: "unsupported element", html: `<body><a href="#details">Details</a><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: "element <a> is not supported"},
		{name: "unsupported attribute", html: `<body><main data-plugin-id="com.example.plugin">ready</main><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: `attribute "data-plugin-id" is not supported`},
		{name: "inline event handler", html: `<body><button onclick="run()">Run</button><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: "inline event handler"},
		{name: "inline style attribute", html: `<body><main style="display:block">ready</main><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: "inline style attribute"},
		{name: "reserved asset binding", html: `<body><img data-redevplugin-asset-binding="asset_fake" alt=""><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: "reserved asset binding attribute"},
		{name: "unsafe input type", html: `<body><input type="file"><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, want: `input type "file" is not supported`},
		{name: "sloppy worker syntax", html: `<body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `with ({ value: 1 }) { void value }`, want: "invalid JavaScript"},
		{name: "static import", html: `<body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `import "./child.js"`, want: "imports and exports are not allowed"},
		{name: "dynamic import", html: `<body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void import("./child.js")`, want: "imports and exports are not allowed"},
		{name: "export", html: `<body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `export const value = 1`, want: "imports and exports are not allowed"},
		{name: "worker wrapper escape", html: `<body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `}; globalThis.__redevpluginEscaped = true; const resume = () => {`, want: "invalid JavaScript"},
		{name: "css import", html: `<head><link rel="stylesheet" href="app.css"></head><body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, style: `@import "theme.css";`, want: "@import"},
		{name: "external css url", html: `<head><link rel="stylesheet" href="app.css"></head><body><script type="text/redevplugin-worker" src="app.js"></script></body>`, script: `void 0`, style: `body{background:url(https://example.com/x.png)}`, want: "package-local"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{"ui/index.html": []byte(tc.html)}
			if tc.script != "" {
				files["ui/app.js"] = []byte(tc.script)
				files["ui/other.js"] = []byte(tc.script)
			}
			if tc.style != "" {
				files["ui/app.css"] = []byte(tc.style)
			}
			files["ui/child.html"] = []byte(`<p>child</p>`)
			files["ui/child.js"] = []byte(`void 0`)
			files["ui/theme.css"] = []byte(`body{color:black}`)
			assets := surfaceTestAssets(t, files)
			_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
				asset, ok := assets[assetPath]
				if !ok {
					return Asset{}, fmt.Errorf("missing asset %s", assetPath)
				}
				return asset, nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestBuildOpaqueSurfaceDocumentCanonicalizesSafeInputTypes(t *testing.T) {
	assets := surfaceTestAssets(t, map[string][]byte{
		"ui/index.html": []byte(`<body><input id="trimmed" type=" TEXT "><input id="empty" type=""><script type="text/redevplugin-worker" src="app.js"></script></body>`),
		"ui/app.js":     []byte(`void 0`),
	})
	document, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
		return assets[assetPath], nil
	})
	if err != nil {
		t.Fatalf("BuildOpaqueSurfaceDocument() error = %v", err)
	}
	if strings.Count(document.BodyHTML, `type="text"`) != 2 || strings.Contains(document.BodyHTML, " TEXT ") {
		t.Fatalf("input types were not canonicalized: %s", document.BodyHTML)
	}
}

func TestBuildOpaqueSurfaceDocumentRecomputesEveryAssetDigest(t *testing.T) {
	assets := surfaceTestAssets(t, map[string][]byte{
		"ui/index.html": []byte(`<body><script type="text/redevplugin-worker" src="app.js"></script></body>`),
		"ui/app.js":     []byte(`void 0`),
	})
	corrupt := assets["ui/app.js"]
	corrupt.Entry.SHA256 = "sha256:" + strings.Repeat("0", 64)
	assets["ui/app.js"] = corrupt

	_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
		return assets[assetPath], nil
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 metadata mismatch") {
		t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want digest mismatch", err)
	}
}

func surfaceTestAssets(t *testing.T, files map[string][]byte) map[string]Asset {
	t.Helper()
	assets := make(map[string]Asset, len(files))
	for assetPath, content := range files {
		entry, err := makeEntry(assetPath, content)
		if err != nil {
			t.Fatalf("makeEntry(%q) error = %v", assetPath, err)
		}
		assets[assetPath] = Asset{Entry: entry, Content: content}
	}
	return assets
}
