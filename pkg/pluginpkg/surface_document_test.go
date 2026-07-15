package pluginpkg

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
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
		"ui/assets/icon.png":         surfaceTestPNG(t, 24, 24),
		"ui/assets/background.png":   surfaceTestPNG(t, 64, 32),
		"ui/assets/unreferenced.png": surfaceTestPNG(t, 1, 1),
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

func TestBuildOpaqueSurfaceDocumentDeclaresCanvasAndLogicalImageAssets(t *testing.T) {
	assets := surfaceTestAssets(t, map[string][]byte{
		"ui/index.html": []byte(`<!doctype html>
<html lang="en">
  <head>
    <title>Sky Strike</title>
    <link rel="redevplugin-image" href="assets/player.png" data-redevplugin-asset-id="player-ship">
  </head>
  <body>
    <main>
      <canvas data-redevplugin-canvas="playfield" width="960" height="540" tabindex="0" aria-label="Sky Strike playfield"></canvas>
    </main>
    <script type="text/redevplugin-worker" src="assets/app.js"></script>
  </body>
</html>`),
		"ui/assets/app.js":     []byte(`const bridge = new PluginBridgeClient(); void bridge.ready();`),
		"ui/assets/player.png": surfaceTestPNG(t, 64, 64),
	})
	document, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
		asset, ok := assets[assetPath]
		if !ok {
			return Asset{}, fmt.Errorf("missing asset %s", assetPath)
		}
		return asset, nil
	})
	if err != nil {
		t.Fatalf("BuildOpaqueSurfaceDocument() error = %v", err)
	}
	if !strings.Contains(document.BodyHTML, `data-redevplugin-canvas="playfield"`) || !strings.Contains(document.BodyHTML, `width="960"`) || !strings.Contains(document.BodyHTML, `height="540"`) {
		t.Fatalf("canvas declaration was not retained: %s", document.BodyHTML)
	}
	if len(document.Assets) != 1 {
		t.Fatalf("assets = %#v, want one declared image", document.Assets)
	}
	if got := document.Assets[0].LogicalIDs; len(got) != 1 || got[0] != "player-ship" {
		t.Fatalf("logical asset ids = %#v, want player-ship", got)
	}
	if document.Assets[0].Path != "ui/assets/player.png" || document.Assets[0].ContentType != "image/png" {
		t.Fatalf("logical asset metadata mismatch: %#v", document.Assets[0])
	}
}

func TestMakeEntryDetectsRasterContentTypeFromBytes(t *testing.T) {
	entry, err := makeEntry("ui/assets/player.bin", []byte{137, 80, 78, 71, 13, 10, 26, 10})
	if err != nil {
		t.Fatalf("makeEntry() error = %v", err)
	}
	if entry.ContentType != "image/png" {
		t.Fatalf("content type = %q, want image/png", entry.ContentType)
	}
}

func TestBuildOpaqueSurfaceDocumentRejectsAmbiguousInteractiveIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "duplicate canvas id",
			html: `<body><canvas data-redevplugin-canvas="game"></canvas><canvas data-redevplugin-canvas="game"></canvas><script type="text/redevplugin-worker" src="app.js"></script></body>`,
			want: `canvas identifier "game" must be unique`,
		},
		{
			name: "canvas marker on non canvas",
			html: `<body><div data-redevplugin-canvas="game"></div><script type="text/redevplugin-worker" src="app.js"></script></body>`,
			want: `attribute "data-redevplugin-canvas" is not supported`,
		},
		{
			name: "duplicate logical asset id",
			html: `<head><link rel="redevplugin-image" href="one.png" data-redevplugin-asset-id="ship"><link rel="redevplugin-image" href="two.png" data-redevplugin-asset-id="ship"></head><body><script type="text/redevplugin-worker" src="app.js"></script></body>`,
			want: `asset identifier "ship" must be unique`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assets := surfaceTestAssets(t, map[string][]byte{
				"ui/index.html": []byte(tc.html),
				"ui/app.js":     []byte(`void 0`),
				"ui/one.png":    surfaceTestPNG(t, 1, 1),
				"ui/two.png":    surfaceTestPNG(t, 1, 1),
			})
			_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
				asset, ok := assets[assetPath]
				if !ok {
					return Asset{}, fmt.Errorf("missing asset %s", assetPath)
				}
				return asset, nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildOpaqueSurfaceDocumentBoundsLazyAssetResources(t *testing.T) {
	t.Run("asset count", func(t *testing.T) {
		files := map[string][]byte{"ui/app.js": []byte("void 0")}
		var body strings.Builder
		body.WriteString(`<body>`)
		for i := 0; i < 129; i++ {
			assetPath := fmt.Sprintf("ui/asset-%03d.bin", i)
			files[assetPath] = []byte{byte(i)}
			fmt.Fprintf(&body, `<audio src="asset-%03d.bin"></audio>`, i)
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
			"ui/index.html": []byte(`<body><audio src="large.bin"></audio><script type="text/redevplugin-worker" src="app.js"></script></body>`),
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

func TestBuildOpaqueSurfaceDocumentBoundsCanvasResources(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "dimension",
			body: `<canvas data-redevplugin-canvas="game" width="4097" height="1"></canvas>`,
			want: "must be an integer from 1 to 4096",
		},
		{
			name: "count",
			body: `<canvas data-redevplugin-canvas="one"></canvas><canvas data-redevplugin-canvas="two"></canvas><canvas data-redevplugin-canvas="three"></canvas><canvas data-redevplugin-canvas="four"></canvas><canvas data-redevplugin-canvas="five"></canvas>`,
			want: "canvas count exceeds 4",
		},
		{
			name: "total pixels",
			body: `<canvas data-redevplugin-canvas="one" width="4096" height="4096"></canvas><canvas data-redevplugin-canvas="two" width="1" height="1"></canvas>`,
			want: "canvas pixels exceed 16777216",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assets := surfaceTestAssets(t, map[string][]byte{
				"ui/index.html": []byte(`<body>` + tc.body + `<script type="text/redevplugin-worker" src="app.js"></script></body>`),
				"ui/app.js":     []byte(`void 0`),
			})
			_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
				return assets[assetPath], nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildOpaqueSurfaceDocumentBoundsDecodedImageResources(t *testing.T) {
	t.Run("dimension", func(t *testing.T) {
		assets := surfaceTestAssets(t, map[string][]byte{
			"ui/index.html": []byte(`<body><img alt="" src="wide.png"><script type="text/redevplugin-worker" src="app.js"></script></body>`),
			"ui/app.js":     []byte(`void 0`),
			"ui/wide.png":   surfaceTestPNG(t, 4097, 1),
		})
		_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
			return assets[assetPath], nil
		})
		if err == nil || !strings.Contains(err.Error(), "image dimensions exceed 4096") {
			t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want image dimension limit", err)
		}
	})

	t.Run("count", func(t *testing.T) {
		files := map[string][]byte{"ui/app.js": []byte(`void 0`)}
		var body strings.Builder
		body.WriteString(`<body>`)
		for i := 0; i < opaqueSurfaceMaxImageCount+1; i++ {
			assetPath := fmt.Sprintf("ui/image-%02d.png", i)
			files[assetPath] = surfaceTestPNG(t, 1, 1)
			fmt.Fprintf(&body, `<img alt="" src="image-%02d.png">`, i)
		}
		body.WriteString(`<script type="text/redevplugin-worker" src="app.js"></script></body>`)
		files["ui/index.html"] = []byte(body.String())
		assets := surfaceTestAssets(t, files)
		_, err := BuildOpaqueSurfaceDocument("ui/index.html", func(assetPath string) (Asset, error) {
			return assets[assetPath], nil
		})
		if err == nil || !strings.Contains(err.Error(), "image count exceeds 32") {
			t.Fatalf("BuildOpaqueSurfaceDocument() error = %v, want image count limit", err)
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

func surfaceTestPNG(t *testing.T, width int, height int) []byte {
	t.Helper()
	imageData := image.NewNRGBA(image.Rect(0, 0, width, height))
	imageData.Set(0, 0, color.NRGBA{R: 24, G: 32, B: 48, A: 255})
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, imageData); err != nil {
		t.Fatalf("png.Encode(%dx%d) error = %v", width, height, err)
	}
	return encoded.Bytes()
}
