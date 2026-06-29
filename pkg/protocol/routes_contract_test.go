package protocol

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/floegence/redevplugin/pkg/httpadapter"
)

type routeFixture struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func TestHTTPRouteSetMatchesFixture(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "contracts", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []routeFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}

	got := make([]routeFixture, 0, len(httpadapter.RouteSet()))
	for _, route := range httpadapter.RouteSet() {
		got = append(got, routeFixture{Method: route.Method, Path: route.Path})
	}
	sortRoutes(fixtures)
	sortRoutes(got)
	if !reflect.DeepEqual(got, fixtures) {
		t.Fatalf("route set mismatch\n got: %#v\nwant: %#v", got, fixtures)
	}
}

func TestHTTPRouteSetMatchesOpenAPI(t *testing.T) {
	root := repoRoot(t)
	openAPIRoutes, err := readOpenAPIRoutes(filepath.Join(root, "spec", "openapi", "plugin-platform-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	got := make([]routeFixture, 0, len(httpadapter.RouteSet()))
	for _, route := range httpadapter.RouteSet() {
		got = append(got, routeFixture{Method: route.Method, Path: route.Path})
	}
	sortRoutes(openAPIRoutes)
	sortRoutes(got)
	if !reflect.DeepEqual(got, openAPIRoutes) {
		t.Fatalf("OpenAPI route set mismatch\n got: %#v\nwant: %#v", got, openAPIRoutes)
	}
}

func readOpenAPIRoutes(path string) ([]routeFixture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var routes []routeFixture
	var currentPath string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "components:") {
			currentPath = ""
			continue
		}
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			currentPath = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if currentPath == "" {
			continue
		}
		switch line {
		case "    get:":
			routes = append(routes, routeFixture{Method: "GET", Path: currentPath})
		case "    patch:":
			routes = append(routes, routeFixture{Method: "PATCH", Path: currentPath})
		case "    post:":
			routes = append(routes, routeFixture{Method: "POST", Path: currentPath})
		}
	}
	return routes, scanner.Err()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	var _, file, _, _ = runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func sortRoutes(routes []routeFixture) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
}
