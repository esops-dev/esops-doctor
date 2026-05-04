package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenClusterClientImports asserts that nothing under
// internal/... or cmd/... transitively imports a raw Elasticsearch or
// OpenSearch Go client. The read-only-by-construction guarantee depends
// on every cluster touch routing through esops-go/pkg/client; a direct
// import of either upstream client would let a mutating call slip past
// the boundary, defeating the headline guarantee.
func TestNoForbiddenClusterClientImports(t *testing.T) {
	forbidden := []string{
		"github.com/elastic/go-elasticsearch",
		"github.com/opensearch-project/opensearch-go",
	}

	out, err := exec.Command(
		"go", "list", "-deps", "-f", "{{.ImportPath}}",
		"github.com/esops-dev/esops-doctor/cmd/...",
		"github.com/esops-dev/esops-doctor/internal/...",
	).Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	var hits []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, prefix := range forbidden {
			if line == prefix || strings.HasPrefix(line, prefix+"/") {
				hits = append(hits, line)
			}
		}
	}
	if len(hits) > 0 {
		t.Fatalf("forbidden cluster client in transitive import graph:\n  %s\nroute every cluster touch through esops-go/pkg/client",
			strings.Join(hits, "\n  "))
	}
}

// pkgClientImportPath is the only allowed entry point for cluster I/O.
// The mutating-capability guard scopes itself to files that import this
// path so it can't false-positive on unrelated identifiers in unrelated
// packages.
const pkgClientImportPath = "github.com/esops-dev/esops-go/pkg/client"

// forbiddenCapabilityRefs lists every symbol whose presence in a
// non-test file under internal/... or cmd/... would break the
// read-only-by-construction guarantee: every mutating capability
// interface, plus the write methods on ILMManager / ISMManager. The
// value is the human-readable category used in the failure message.
var forbiddenCapabilityRefs = map[string]string{
	"Reindexer":                 "mutating capability",
	"IndexStateChanger":         "mutating capability",
	"IndexOptimizer":            "mutating capability",
	"IndexShrinker":             "mutating capability",
	"IndexSettingsUpdater":      "mutating capability",
	"IndexTemplateUpdater":      "mutating capability",
	"AliasUpdater":              "mutating capability",
	"SnapshotCreator":           "mutating capability",
	"SnapshotRestorer":          "mutating capability",
	"SnapshotPruner":            "mutating capability",
	"SnapshotRepositoryManager": "mutating capability",
	"ClusterSettingsManager":    "mutating capability",
	"RerouteExecutor":           "mutating capability",
	"VotingExclusionManager":    "mutating capability",
	"TasksCanceller":            "mutating capability",
	"PutPolicy":                 "ILM/ISM write method",
	"DeletePolicy":              "ILM/ISM write method",
}

// TestNoMutatingCapabilityReferences asserts that no production source
// file (under internal/... or cmd/..., excluding _test.go) references
// a mutating capability or write method from esops-go/pkg/client. Paired
// with TestNoForbiddenClusterClientImports, this is the load-bearing
// check that doctor is read-only not by review discipline but by source
// inspection.
//
// Implementation: parse each .go file with go/parser, and only scan
// files that import pkg/client. In those files, every SelectorExpr
// whose Sel.Name appears in forbiddenCapabilityRefs is a hit —
// regardless of whether the X side is the package alias (typed-use of
// a mutating interface) or a value of an interface type from the
// package (call to a write method). Both shapes are signals of
// mutating intent in a file that has no read-side reason to import
// pkg/client.
//
// No type checker, so no esops-go module dependency is required for
// this check to be valid; today every file in the tree passes
// trivially because nothing imports pkg/client yet, and the guard
// starts firing as soon as a probe lands.
func TestNoMutatingCapabilityReferences(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	modRoot := strings.TrimSpace(string(out))

	fset := token.NewFileSet()
	var hits []string

	for _, sub := range []string{"internal", "cmd"} {
		root := filepath.Join(modRoot, sub)
		if _, err := filepath.Glob(root); err != nil {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}

			usesPkgClient := false
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) == pkgClientImportPath {
					usesPkgClient = true
					break
				}
			}
			if !usesPkgClient {
				return nil
			}

			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				kind, banned := forbiddenCapabilityRefs[sel.Sel.Name]
				if !banned {
					return true
				}
				rel, _ := filepath.Rel(modRoot, path)
				pos := fset.Position(sel.Pos())
				hits = append(hits, fmt.Sprintf("%s:%d: %s (%s)", rel, pos.Line, sel.Sel.Name, kind))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(hits) > 0 {
		t.Fatalf("forbidden mutating references in production sources:\n  %s\nuse only read-side capabilities; cluster mutations belong in esops, not doctor",
			strings.Join(hits, "\n  "))
	}
}
