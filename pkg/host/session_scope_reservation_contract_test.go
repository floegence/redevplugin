package host

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSessionScopedPublicResourcePathsHoldReservationThroughMutation(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	hostFile := filepath.Join(filepath.Dir(currentFile), "host.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), hostFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{
		"OpenSurface": false, "PrepareSurface": false, "DisposeSurface": false,
		"MintBridgeToken": false, "CallPluginMethod": false, "PrepareMethodConfirmation": false,
		"RejectMethodConfirmation": false,
		"InvokeIntent":             false, "CancelOperation": false, "CancelSurfaceOperation": false,
		"ReadStream": false, "AcknowledgeStream": false,
		"MintConnectionGrant": false, "MintNetworkHandleGrant": false, "MintStorageHandleGrant": false,
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv == nil || function.Body == nil {
			continue
		}
		if _, tracked := required[function.Name.Name]; !tracked {
			continue
		}
		reserved := false
		releasedByDefer := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch current := node.(type) {
			case *ast.CallExpr:
				if selector, ok := current.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "reserveAuthorizedAction" {
					reserved = true
				}
			case *ast.DeferStmt:
				if identifier, ok := current.Call.Fun.(*ast.Ident); ok && identifier.Name == "releaseReservation" {
					releasedByDefer = true
				}
			}
			return true
		})
		if !reserved || !releasedByDefer {
			t.Errorf("%s must reserve the authenticated session and defer release through every resource mutation", function.Name.Name)
		}
		required[function.Name.Name] = true
	}
	for function, found := range required {
		if !found {
			t.Errorf("required session-scoped public path %s was not found", function)
		}
	}
}
