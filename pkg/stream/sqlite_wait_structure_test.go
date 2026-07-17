package stream

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSQLiteWaitHasOneEventDrivenBlockingPoint(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate SQLite wait structure test")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(filepath.Dir(testFile), "sqlite.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wait := findFunction(t, file, "Wait", "SQLiteStore")
	block := findFunction(t, file, "waitForStreamNotification", "")
	assertNoPollingSyntax(t, wait)
	assertNoPollingSyntax(t, block)

	blockCalls := callPositions(wait, "waitForStreamNotification")
	if len(blockCalls) != 1 {
		t.Fatalf("SQLiteStore.Wait waitForStreamNotification calls = %d, want 1", len(blockCalls))
	}
	blockPosition := blockCalls[0]
	lastStatement := wait.Body.List[len(wait.Body.List)-1]
	lastReturn, ok := lastStatement.(*ast.ReturnStmt)
	if !ok || len(lastReturn.Results) != 1 {
		t.Fatal("SQLiteStore.Wait must end by directly returning its blocking helper")
	}
	lastCall, ok := lastReturn.Results[0].(*ast.CallExpr)
	if !ok || calledName(lastCall.Fun) != "waitForStreamNotification" {
		t.Fatal("SQLiteStore.Wait has executable logic after its observation phase")
	}
	observations := callPositions(wait, "observeQuery")
	if len(observations) != 3 {
		t.Fatalf("SQLiteStore.Wait observeQuery calls = %d, want 3 initial observations", len(observations))
	}
	for _, position := range observations {
		if position > blockPosition {
			t.Fatal("SQLiteStore.Wait observes storage after entering its blocking point")
		}
	}
	selects := nodesOfType[*ast.SelectStmt](block)
	if len(selects) != 1 {
		t.Fatalf("waitForStreamNotification select statements = %d, want 1", len(selects))
	}
	if clauses := selects[0].Body.List; len(clauses) != 3 {
		t.Fatalf("waitForStreamNotification select clauses = %d, want 3", len(clauses))
	} else {
		for _, clause := range clauses {
			if clause.(*ast.CommClause).Comm == nil {
				t.Fatal("waitForStreamNotification must not contain a default clause")
			}
		}
	}
	if got := len(nodesOfType[*ast.SelectStmt](wait)); got != 0 {
		t.Fatalf("SQLiteStore.Wait select statements = %d, want 0", got)
	}
	for _, name := range []string{"QueryContext", "QueryRowContext", "ExecContext", "BeginTx", "observeQuery"} {
		if calls := callPositions(block, name); len(calls) != 0 {
			t.Fatalf("waitForStreamNotification contains storage call %s", name)
		}
	}
}

func findFunction(t *testing.T, file *ast.File, name string, receiver string) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name {
			continue
		}
		if receiver == "" && function.Recv == nil {
			return function
		}
		if receiver != "" && function.Recv != nil && len(function.Recv.List) == 1 {
			typeExpression := function.Recv.List[0].Type
			if pointer, ok := typeExpression.(*ast.StarExpr); ok {
				typeExpression = pointer.X
			}
			if identifier, ok := typeExpression.(*ast.Ident); ok && identifier.Name == receiver {
				return function
			}
		}
	}
	t.Fatalf("function %s was not found", name)
	return nil
}

func assertNoPollingSyntax(t *testing.T, function *ast.FuncDecl) {
	t.Helper()
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			t.Fatalf("%s contains polling loop %T", function.Name.Name, typed)
		case *ast.CallExpr:
			name := calledName(typed.Fun)
			switch name {
			case function.Name.Name, "After", "NewTicker", "NewTimer", "Reset", "Sleep":
				t.Fatalf("%s contains polling or recursive call %s", function.Name.Name, name)
			}
		}
		return true
	})
}

func callPositions(function *ast.FuncDecl, name string) []token.Pos {
	positions := []token.Pos{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && calledName(call.Fun) == name {
			positions = append(positions, call.Pos())
		}
		return true
	})
	return positions
}

func calledName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}

func nodesOfType[T ast.Node](function *ast.FuncDecl) []T {
	nodes := []T{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if typed, ok := node.(T); ok {
			nodes = append(nodes, typed)
		}
		return true
	})
	return nodes
}
