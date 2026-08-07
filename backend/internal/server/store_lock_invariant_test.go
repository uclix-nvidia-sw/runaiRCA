package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The store's write path depends on two rules that nothing in the compiler,
// the vet suite or the unit tests can see:
//
//  1. Every writer takes writeMu before mu. A writer that skips it can mutate
//     memory in the middle of another writer's persist, and the older row then
//     lands on top of the newer one in Postgres — silently, with the operator's
//     trash/approve reverted and no error anywhere.
//  2. No function takes writeMu twice. It is a plain Mutex, so the second
//     acquisition deadlocks the process. Writing this file cost exactly that:
//     loadKnowledge has four mu.Lock() sites and picked up two writeMu pairs.
//
// Both are properties of the source, so the test reads the source.
func storeSourceFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs[name+":"+fn.Name.Name] = fn
		}
	}
	if len(funcs) == 0 {
		t.Fatal("parsed no functions — the test is looking at the wrong directory")
	}
	return funcs
}

// countLocks reports how often fn locks the STORE's <field>, written either as
// s.<field> from a Store method or s.store.<field> from a Server one.
//
// Both spellings matter. An earlier version accepted only the bare identifier
// `s`, which silently exempted every caller reaching past the Store's own
// methods — and incidentResolve does exactly that with s.store.mu.Lock(),
// persisting an incident with no writeMu at all. The test reported a clean bill
// of health on a writer that could still lose an update. Accepting ANY receiver
// is the other failure: Hub.mu and slackState.mu are unrelated mutexes and get
// reported as violations.
func countLocks(fn *ast.FuncDecl, field string) int {
	storeLock := func(expr ast.Expr) bool {
		switch base := expr.(type) {
		case *ast.Ident: // s.<field>, inside a Store method
			return base.Name == "s" && isStoreMethod(fn)
		case *ast.SelectorExpr: // s.store.<field>, from a Server
			return base.Sel.Name == "store"
		}
		return false
	}
	n := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		outer, ok := call.Fun.(*ast.SelectorExpr) // ....Lock
		if !ok || outer.Sel.Name != "Lock" {
			return true
		}
		inner, ok := outer.X.(*ast.SelectorExpr) // ....<field>
		if !ok || inner.Sel.Name != field || !storeLock(inner.X) {
			return true
		}
		n++
		return true
	})
	return n
}

// isStoreMethod reports whether fn is a method on *Store, so that a bare `s.mu`
// in some other type's method is not mistaken for the store lock.
func isStoreMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	ident, ok := star.X.(*ast.Ident)
	return ok && ident.Name == "Store"
}

func TestEveryStoreWriterTakesWriteMu(t *testing.T) {
	var missing []string
	for name, fn := range storeSourceFuncs(t) {
		if countLocks(fn, "mu") > 0 && countLocks(fn, "writeMu") == 0 {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("these writers take s.mu.Lock() without s.writeMu.Lock(): %v\n"+
			"A writer that skips writeMu can mutate memory during another writer's "+
			"persist, and the stale row then overwrites the fresh one in Postgres.", missing)
	}
}

func TestNoStoreFunctionTakesWriteMuTwice(t *testing.T) {
	var doubled []string
	for name, fn := range storeSourceFuncs(t) {
		if countLocks(fn, "writeMu") > 1 {
			doubled = append(doubled, name)
		}
	}
	if len(doubled) > 0 {
		t.Fatalf("these functions acquire s.writeMu more than once and will deadlock: %v\n"+
			"One deferred acquisition covers a function with several mu.Lock() blocks.", doubled)
	}
}
