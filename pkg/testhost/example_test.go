package testhost_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/floegence/redevplugin/v3/pkg/host"
	"github.com/floegence/redevplugin/v3/pkg/testhost"
)

func ExampleOpen() {
	harness, err := testhost.Open(context.Background(), testhost.Options{
		ParentOrigin: "http://localhost:43210",
		Actions:      []host.ManagementAction{host.ManagementActionListPlugins},
	})
	if err != nil {
		panic(err)
	}
	defer harness.Close()
	plugins, err := harness.Host().ListPlugins(harness.Context(context.Background()))
	if err != nil {
		panic(err)
	}
	request, err := harness.NewRequest(context.Background(), http.MethodPost, "/_redevplugin/api/plugins/catalog/query", strings.NewReader("{}"))
	if err != nil {
		panic(err)
	}
	response := httptest.NewRecorder()
	harness.Handler(nil).ServeHTTP(response, request)
	fmt.Println("installed plugins:", len(plugins))
	fmt.Println("authenticated HTTP:", response.Code)
	// Output:
	// installed plugins: 0
	// authenticated HTTP: 200
}
