package examples_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/manifest"
	"github.com/floegence/redevplugin/pkg/pluginpkg"
)

func TestExamplesAreTheOnlyUserFacingPluginShowcase(t *testing.T) {
	root := repositoryRoot(t)
	if _, err := os.Stat(filepath.Join(root, "demo")); !os.IsNotExist(err) {
		t.Fatalf("demo/ must not exist after the examples consolidation: %v", err)
	}
	for _, path := range []string{
		"examples/showcase/index.html",
		"examples/showcase/styles.css",
		"examples/showcase/app.js",
		"examples/plugins/worker-artifacts.lock.json",
		"internal/browserharness/opaque-surface-contract.test.mjs",
		"internal/browserharness/opaque-surface-server.mjs",
		"internal/browserharness/opaque-surface-smoke.mjs",
		"testdata/browser-harness/opaque-surface/index.html",
		"testdata/browser-harness/opaque-surface/host.mjs",
		"testdata/browser-harness/opaque-surface/generated/plugin-worker.js",
		"internal/scaffoldtemplate/plugin-worker.ts",
		"cmd/redevplugin/scaffold_assets/plugin-worker.js",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
			t.Fatalf("required consolidated path %s is unavailable: %v", path, err)
		}
	}
}

func TestExampleWorkerArtifactsUseCanonicalLinuxBuildAndSourceLock(t *testing.T) {
	root := repositoryRoot(t)
	scriptRaw, err := os.ReadFile(filepath.Join(root, "scripts", "build_example_plugins.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptRaw)
	for _, required := range []string{
		`const forceCanonical = args.includes("--canonical");`,
		`const workerArtifactLockPath = "examples/plugins/worker-artifacts.lock.json";`,
		`process.platform === "linux" && process.arch === "x64"`,
		`"--platform", "linux/amd64"`,
		`rust:${rustVersion}-bookworm`,
		`schema_version: "redevplugin.example_worker_artifacts.v1"`,
		`source_files: sourceHashes`,
		`artifacts: artifactHashes`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("example worker builder missing canonical artifact contract %q", required)
		}
	}

	packageRaw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(packageRaw), `"examples:check:canonical": "node scripts/build_example_plugins.mjs --check --canonical"`) {
		t.Fatal("package scripts must expose the canonical example worker check")
	}

	ciRaw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ci := string(ciRaw)
	contractsStart := strings.Index(ci, "  contracts:\n")
	releaseSmokeStart := strings.Index(ci, "  release-bundle-smoke:\n")
	if contractsStart < 0 || releaseSmokeStart <= contractsStart {
		t.Fatal("CI workflow is missing the Platform Contracts job boundary")
	}
	contractsJob := ci[contractsStart:releaseSmokeStart]
	if !strings.Contains(contractsJob, "rustup target add wasm32-unknown-unknown") {
		t.Fatal("Platform Contracts must install wasm32-unknown-unknown before platform checks")
	}

	lockRaw, err := os.ReadFile(filepath.Join(root, "examples", "plugins", "worker-artifacts.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		SchemaVersion string            `json:"schema_version"`
		RustVersion   string            `json:"rust_version"`
		SourceFiles   map[string]string `json:"source_files"`
		Artifacts     map[string]string `json:"artifacts"`
	}
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.SchemaVersion != "redevplugin.example_worker_artifacts.v1" || lock.RustVersion != "1.88.0" {
		t.Fatalf("worker artifact lock identity = %q/%q", lock.SchemaVersion, lock.RustVersion)
	}
	if len(lock.SourceFiles) < 10 {
		t.Fatalf("worker artifact source lock has only %d inputs", len(lock.SourceFiles))
	}
	wantArtifacts := []string{
		"examples/plugins/memos/workers/memos.wasm",
		"examples/plugins/sky-strike/workers/sky-strike.wasm",
		"examples/plugins/weather/workers/weather.wasm",
	}
	if len(lock.Artifacts) != len(wantArtifacts) {
		t.Fatalf("worker artifact lock entries = %v", lock.Artifacts)
	}
	for _, path := range wantArtifacts {
		if digest := lock.Artifacts[path]; len(digest) != 64 {
			t.Fatalf("worker artifact %s digest = %q", path, digest)
		}
	}
}

func TestExamplePluginPackagesAreCompleteAndInstallable(t *testing.T) {
	root := repositoryRoot(t)
	wants := map[string]struct {
		pluginID string
		methods  []string
		stores   []string
		hosts    []string
	}{
		"memos": {
			pluginID: "dev.redevplugin.examples.memos",
			methods:  []string{"memos.delete", "memos.get", "memos.initialize", "memos.list", "memos.save", "memos.togglePin"},
			stores:   []string{"memos"},
		},
		"weather": {
			pluginID: "dev.redevplugin.examples.weather",
			methods:  []string{"weather.forecast", "weather.initialize", "weather.locations.list", "weather.locations.remove", "weather.locations.save", "weather.locations.search"},
			stores:   []string{"weather"},
			hosts:    []string{"api.open-meteo.com", "geocoding-api.open-meteo.com"},
		},
		"sky-strike": {
			pluginID: "dev.redevplugin.examples.sky-strike",
			methods:  []string{"game.highScore.load", "game.highScore.save", "game.initialize"},
			stores:   []string{"game"},
		},
	}

	entries, err := os.ReadDir(filepath.Join(root, "examples", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	gotNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			gotNames = append(gotNames, entry.Name())
		}
	}
	sort.Strings(gotNames)
	if strings.Join(gotNames, ",") != "memos,sky-strike,weather" {
		t.Fatalf("example plugin directories = %v", gotNames)
	}

	for name, want := range wants {
		t.Run(name, func(t *testing.T) {
			packageRoot := filepath.Join(root, "examples", "plugins", name)
			var archive strings.Builder
			pkg, err := pluginpkg.BuildFromDir(context.Background(), packageRoot, &archive, pluginpkg.DefaultReadOptions())
			if err != nil {
				t.Fatalf("BuildFromDir(%s) error = %v", name, err)
			}
			if pkg.Manifest.PluginID() != want.pluginID {
				t.Fatalf("plugin id = %q, want %q", pkg.Manifest.PluginID(), want.pluginID)
			}
			assertStringSet(t, "methods", methodNames(pkg.Manifest), want.methods)
			assertStringSet(t, "stores", storeNames(pkg.Manifest), want.stores)
			assertStringSet(t, "network hosts", networkHosts(pkg.Manifest), want.hosts)
			for path := range pkg.Files {
				if strings.HasSuffix(path, ".rs") || filepath.Base(path) == "Cargo.toml" || filepath.Base(path) == "Cargo.lock" {
					t.Fatalf("installable package contains source/build metadata: %s", path)
				}
			}
		})
	}
}

func TestExampleManifestsUseWorkerABIV2WithoutCallerOwnedStorageGrants(t *testing.T) {
	root := repositoryRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "examples", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, "examples", "plugins", entry.Name(), "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "storage_handle_grant_token") {
			t.Fatalf("%s manifest exposes a Host-owned storage grant", entry.Name())
		}
		var doc manifest.Manifest
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, worker := range doc.Workers {
			if worker.ABI != "redevplugin-wasm-worker-v2" {
				t.Fatalf("%s worker %s ABI = %q", entry.Name(), worker.WorkerID, worker.ABI)
			}
		}
	}
}

func TestSQLiteExamplesDeclareMinimalBrokerAccessAndOwnSchemaInitialization(t *testing.T) {
	root := repositoryRoot(t)
	cases := []struct {
		plugin   string
		methods  map[string]string
		database string
	}{
		{
			plugin: "memos",
			methods: map[string]string{
				"memos.initialize": `{"storage":[{"store_id":"memos","operations":["exec"]}]}`,
				"memos.list":       `{"storage":[{"store_id":"memos","operations":["query"]}]}`,
				"memos.get":        `{"storage":[{"store_id":"memos","operations":["query"]}]}`,
				"memos.save":       `{"storage":[{"store_id":"memos","operations":["exec","query"]}]}`,
				"memos.delete":     `{"storage":[{"store_id":"memos","operations":["exec"]}]}`,
				"memos.togglePin":  `{"storage":[{"store_id":"memos","operations":["exec","query"]}]}`,
			},
			database: "memos.sqlite",
		},
		{
			plugin: "weather",
			methods: map[string]string{
				"weather.initialize":       `{"storage":[{"store_id":"weather","operations":["exec"]}]}`,
				"weather.locations.search": `{"network":[{"connector_id":"geocoding","transport":"http","operations":["http"],"http_methods":["GET"]}]}`,
				"weather.locations.list":   `{"storage":[{"store_id":"weather","operations":["query"]}]}`,
				"weather.locations.save":   `{"storage":[{"store_id":"weather","operations":["exec"]}]}`,
				"weather.locations.remove": `{"storage":[{"store_id":"weather","operations":["exec"]}]}`,
				"weather.forecast":         `{"network":[{"connector_id":"forecast","transport":"http","operations":["http"],"http_methods":["GET"]}]}`,
			},
			database: "weather.sqlite",
		},
		{
			plugin: "sky-strike",
			methods: map[string]string{
				"game.initialize":     `{"storage":[{"store_id":"game","operations":["exec"]}]}`,
				"game.highScore.load": `{"storage":[{"store_id":"game","operations":["query"]}]}`,
				"game.highScore.save": `{"storage":[{"store_id":"game","operations":["exec","query"]}]}`,
			},
			database: "sky-strike.sqlite",
		},
	}
	for _, tc := range cases {
		t.Run(tc.plugin, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, "examples", "plugins", tc.plugin, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var doc manifest.Manifest
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			for _, method := range doc.Methods {
				want, ok := tc.methods[method.Method]
				if !ok {
					continue
				}
				got, err := json.Marshal(method.BrokerAccess)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != want {
					t.Fatalf("%s broker access = %s, want %s", method.Method, got, want)
				}
				delete(tc.methods, method.Method)
			}
			if len(tc.methods) != 0 {
				t.Fatalf("missing broker access for methods %v", tc.methods)
			}
			if len(doc.Storage.Stores) != 1 || doc.Storage.Stores[0].Kind != "sqlite" {
				t.Fatal("example must declare exactly one SQLite store")
			}
			if !doc.Storage.Stores[0].Migration.RequiresWorker {
				t.Fatal("SQLite migration must be owned by the worker")
			}
			workerSource, err := os.ReadFile(filepath.Join(root, "examples", "workers", tc.plugin, "src", "lib.rs"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{tc.database, "CREATE TABLE IF NOT EXISTS"} {
				if !strings.Contains(string(workerSource), want) {
					t.Fatalf("%s worker must own idempotent SQLite initialization containing %q", tc.plugin, want)
				}
			}
		})
	}
}

func TestSkyStrikeExposesARealCanvasGameContract(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "examples", "plugin-ui", "sky-strike.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`bridge.openCanvas("playfield")`,
		`bridge.loadImageAsset("starfield-background")`,
		`bridge.loadImageAsset("player-ship")`,
		`bridge.onCanvasInput("playfield"`,
		`game.highScore.load`,
		`game.highScore.save`,
		`FPS ${Math.round(fps)}`,
		`const PORTRAIT_WIDTH = 540`,
		`const PORTRAIT_HEIGHT = 1080`,
	} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("Sky Strike source is missing %q", required)
		}
	}
}

func TestExampleShowcaseShipsOptimizedConsumerArtwork(t *testing.T) {
	root := repositoryRoot(t)
	assets := []struct {
		path    string
		minSize int64
		maxSize int64
	}{
		{path: "examples/showcase/assets/memos-v2.webp", minSize: 4_000, maxSize: 80_000},
		{path: "examples/showcase/assets/weather-v2.webp", minSize: 4_000, maxSize: 80_000},
		{path: "examples/showcase/assets/sky-strike-v2.webp", minSize: 4_000, maxSize: 80_000},
		{path: "examples/plugins/weather/ui/assets/weather-scene-v2.webp", minSize: 100_000, maxSize: 350_000},
		{path: "examples/plugins/sky-strike/ui/assets/starfield-v2.webp", minSize: 100_000, maxSize: 350_000},
	}
	for _, asset := range assets {
		t.Run(filepath.Base(asset.path), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(asset.path)))
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(raw)) < asset.minSize || int64(len(raw)) > asset.maxSize {
				t.Fatalf("asset size = %d, want %d..%d", len(raw), asset.minSize, asset.maxSize)
			}
			if len(raw) < 12 || string(raw[:4]) != "RIFF" || string(raw[8:12]) != "WEBP" {
				t.Fatal("consumer artwork must be an optimized WebP asset")
			}
		})
	}
}

func TestSkyStrikeRedistributesItsAssetLicenseEvidence(t *testing.T) {
	root := repositoryRoot(t)
	pluginNotice, err := os.ReadFile(filepath.Join(root, "examples", "plugins", "sky-strike", "THIRD_PARTY_NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	legalText, err := os.ReadFile(filepath.Join(root, "third_party", "legal", "kenney-space-shooter-remastered", "LICENSE.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Kenney", "CC0 1.0", "creativecommons.org/publicdomain/zero/1.0"} {
		if !strings.Contains(string(pluginNotice), required) {
			t.Fatalf("Sky Strike plugin notice is missing %q", required)
		}
	}
	if !strings.Contains(string(legalText), "Space Shooter (Remastered") || !strings.Contains(string(legalText), "License (CC0)") {
		t.Fatal("redistributed Kenney license text is incomplete")
	}
}

func TestMemosUsesOneAutosaveAndPinInteractionModel(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "examples", "plugin-ui", "memos.ts"))
	if err != nil {
		t.Fatal(err)
	}
	styles, err := os.ReadFile(filepath.Join(root, "examples", "plugins", "memos", "ui", "assets", "styles.css"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	if !strings.Contains(content, `data-redevplugin-action": "set-pinned"`) {
		t.Fatal("Memos must expose one explicit pin action")
	}
	for _, required := range []string{
		`.memo-title`,
		`.editor-pin`,
		`.memo-menu`,
		`cursor: pointer`,
	} {
		if !strings.Contains(string(styles), required) {
			t.Fatalf("Memos styles are missing %q", required)
		}
	}
	for _, forbidden := range []string{`save-now`, `toggle-pin`, `edit-pinned`, `Save now`, `children: ["Done"]`} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("Memos still exposes duplicate save or pin interaction %q", forbidden)
		}
	}
}

func TestMemosUsesBoundedSummariesAndACompleteMobileEditingFlow(t *testing.T) {
	root := repositoryRoot(t)
	uiSource, err := os.ReadFile(filepath.Join(root, "examples", "plugin-ui", "memos.ts"))
	if err != nil {
		t.Fatal(err)
	}
	workerSource, err := os.ReadFile(filepath.Join(root, "examples", "workers", "memos", "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	styles, err := os.ReadFile(filepath.Join(root, "examples", "plugins", "memos", "ui", "assets", "styles.css"))
	if err != nil {
		t.Fatal(err)
	}
	combined := string(uiSource) + string(workerSource) + string(styles)
	for _, required := range []string{
		`memos.get`,
		`scheduleAutosave`,
		`flushDraft`,
		`if (!(await flushDraft())) return`,
		`state.dirty && state.saveState === "error"`,
		`confirm-delete`,
		`cancel-delete`,
		`back-to-list`,
		`load-more-memos`,
		`view-editor`,
		`tag: "button", attributes: { class: "empty-list"`,
		`toggle-memo-menu`,
		`library-overview`,
		`editor-workspace`,
		`memo-context-rail`,
		`--memos-ocean`,
		`max-width: 820px`,
		`max-width: none`,
		`border-radius: 0`,
		`context-stat`,
		`document-kicker`,
		`LIMIT ? OFFSET ?`,
		`substr(body, 1, 180)`,
		`@media (max-width: 760px)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Memos complete-product flow is missing %q", required)
		}
	}
	if strings.Contains(string(workerSource), `"max_rows": 500`) {
		t.Fatal("Memos list must not expose an unbounded full-library worker response")
	}
}

func TestWeatherHasAnImmediateForecastAndDesignedFailureRecovery(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "examples", "plugin-ui", "weather.ts"))
	if err != nil {
		t.Fatal(err)
	}
	styles, err := os.ReadFile(filepath.Join(root, "examples", "plugins", "weather", "ui", "assets", "styles.css"))
	if err != nil {
		t.Fatal(err)
	}
	workerSource, err := os.ReadFile(filepath.Join(root, "examples", "workers", "weather", "src", "lib.rs"))
	if err != nil {
		t.Fatal(err)
	}
	combined := string(source) + string(styles) + string(workerSource)
	for _, required := range []string{
		`DEFAULT_LOCATION`,
		`Explore Berlin`,
		`retry-weather`,
		`friendlyWeatherError`,
		`forecast-toolbar`,
		`current-summary`,
		`weather-story`,
		`weather-glance`,
		`--weather-cloud`,
		`.weather-hero::before`,
		`forecast-scroll`,
		`min-height: 44px`,
		`request.max_response_bytes = Some(393_216)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Weather complete-product flow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"plugin permission was denied", "PLUGIN_PERMISSION_DENIED", "Choose a place", "Starter", `"max_response_bytes": 524288`} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Weather exposes an internal or empty-first-screen message %q", forbidden)
		}
	}
}

func TestSkyStrikeHasExplicitSessionStatesAndDurableScores(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, "examples", "plugin-ui", "sky-strike.ts"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	for _, required := range []string{
		`type GamePhase = "ready" | "running" | "paused" | "game-over"`,
		`let phase: GamePhase = "ready"`,
		`drawPortraitHUD`,
		`inputMode`,
		`PRESS ENTER OR CLICK TO LAUNCH`,
		`PRESS ENTER OR CLICK TO FLY AGAIN`,
		`MISSION PROGRESS`,
		`persistHighScore`,
		`event.type === "hidden"`,
		`event.type === "dispose"`,
		`stopFrameLoop`,
		`frameTimer`,
		`updateCanvasAccessibility`,
		`event.event === "pointermove" && event.buttons === 0`,
		`FPS ${Math.round(fps)}`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("Sky Strike complete game loop is missing %q", required)
		}
	}
}

func TestShowcaseUsesOneProductLayerAndAccessibleSecondaryDetails(t *testing.T) {
	root := repositoryRoot(t)
	markup, err := os.ReadFile(filepath.Join(root, "examples", "showcase", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(root, "examples", "showcase", "app.ts"))
	if err != nil {
		t.Fatal(err)
	}
	styles, err := os.ReadFile(filepath.Join(root, "examples", "showcase", "styles.css"))
	if err != nil {
		t.Fatal(err)
	}
	combined := string(markup) + string(source) + string(styles)
	for _, required := range []string{
		`plugin-dock`,
		`mobile-plugin-navigation`,
		`mobile-inspector-toggle`,
		`developer-details`,
		`aria-hidden`,
		`.inert`,
		`focus({ preventScroll: true })`,
		`@media (max-width: 820px)`,
		`@media (max-width: 360px)`,
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Showcase responsive shell is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		`desktop-workspace-header`,
		`mobile-workspace-header`,
		`surface-status`,
		`WASM worker`,
		`Opaque sandbox`,
		`plugins ready`,
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Showcase still exposes a duplicate app header or developer-first copy %q", forbidden)
		}
	}
}

func TestExampleInterfacesUseDistinctConsumerProductDesigns(t *testing.T) {
	root := repositoryRoot(t)
	cases := []struct {
		name      string
		paths     []string
		required  []string
		forbidden []string
	}{
		{
			name:      "showcase gallery",
			paths:     []string{"examples/showcase/index.html", "examples/showcase/styles.css"},
			required:  []string{"gallery-shell", "plugin-inspector", "plugin-dock", "inspector-toggle", "inspector-close", "mobile-plugin-navigation", "developer-details", "data-open", "--showcase-shell"},
			forbidden: []string{"grid-template-columns: minmax(0, 1fr) 274px"},
		},
		{
			name:     "memos writing app",
			paths:    []string{"examples/plugins/memos/ui/assets/styles.css", "examples/plugin-ui/memos.ts"},
			required: []string{"memo-library", "library-overview", "editor-toolbar", "editor-workspace", "memo-context-rail", "editor-meta", "word-count", "memo-menu", "delete-confirmation", "mobile-editor-bar", "--memos-coral", "--memos-mint", "--memos-ocean"},
		},
		{
			name:      "weather lifestyle app",
			paths:     []string{"examples/plugins/weather/ui/assets/styles.css", "examples/plugin-ui/weather.ts"},
			required:  []string{"weather-hero", "weather-story", "weather-glance", "weather-metrics", "forecast-icon", "saved-strip", "search-results", "forecast-toolbar", "weather-error", "weather-scene-v2.webp", "--weather-cloud", ".weather-hero::before"},
			forbidden: []string{`return "SUN"`, `return "CLD"`, `return "RAN"`, `class: "saved-panel"`},
		},
		{
			name:      "sky strike arcade",
			paths:     []string{"examples/plugins/sky-strike/ui/index.html", "examples/plugins/sky-strike/ui/assets/styles.css"},
			required:  []string{"arcade-shell", "canvas-stage", "game-actions", "control-hint", "starfield-v2.webp", "starfield-background"},
			forbidden: []string{"cockpit-header", "canvas-frame", "cockpit-status", "mission-control", "Move: WASD", "Fire: Space"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var combined strings.Builder
			for _, path := range tc.paths {
				raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
				if err != nil {
					t.Fatal(err)
				}
				combined.Write(raw)
			}
			content := combined.String()
			for _, required := range tc.required {
				if !strings.Contains(content, required) {
					t.Fatalf("consumer product design is missing %q", required)
				}
			}
			for _, forbidden := range append(tc.forbidden, "font-family: Inter") {
				if strings.Contains(content, forbidden) {
					t.Fatalf("consumer product design still contains %q", forbidden)
				}
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func methodNames(doc manifest.Manifest) []string {
	values := make([]string, 0, len(doc.Methods))
	for _, method := range doc.Methods {
		values = append(values, method.Method)
	}
	return values
}

func storeNames(doc manifest.Manifest) []string {
	if doc.Storage == nil {
		return nil
	}
	values := make([]string, 0, len(doc.Storage.Stores))
	for _, store := range doc.Storage.Stores {
		values = append(values, store.StoreID)
	}
	return values
}

func networkHosts(doc manifest.Manifest) []string {
	if doc.NetworkAccess == nil {
		return nil
	}
	values := make([]string, 0)
	for _, connector := range doc.NetworkAccess.Connectors {
		for _, destination := range connector.Destinations {
			destination = strings.TrimPrefix(destination, "https://")
			destination = strings.TrimPrefix(destination, "http://")
			values = append(values, strings.Split(destination, ":")[0])
		}
	}
	return values
}

func assertStringSet(t *testing.T, label string, got []string, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
}
