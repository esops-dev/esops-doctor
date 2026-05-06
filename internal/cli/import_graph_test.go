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

// TestNoForbiddenClusterClientImports asserts that no doctor source
// file directly imports a raw Elasticsearch or OpenSearch Go client.
// Direct imports would let a mutating call slip past the read-only
// pkg/client surface and defeat the headline guarantee.
//
// The check is direct-imports-only — transitive presence is unavoidable
// once anything in doctor imports esops-go/pkg/cluster, which legitimately
// composes the upstream client adapters and brings the elastic /
// opensearch / aws / otel transports along as `// indirect` go.sum
// entries. (OTEL specifically: doctor itself never imports any OTEL
// package; it only appears indirect via the upstream client transport.)
// Direct imports are what we ban; transitive presence under the
// upstream's hood is what `pkg/cluster` exists to encapsulate.
func TestNoForbiddenClusterClientImports(t *testing.T) {
	forbidden := []string{
		"github.com/elastic/go-elasticsearch",
		"github.com/opensearch-project/opensearch-go",
	}

	hits, err := scanDoctorImports(func(importPath string) string {
		for _, prefix := range forbidden {
			if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
				return "raw cluster client"
			}
		}
		return ""
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(hits) > 0 {
		t.Fatalf("forbidden raw cluster client imported directly:\n  %s\nroute every cluster touch through esops-go/pkg/client (and pkg/cluster for construction)",
			strings.Join(hits, "\n  "))
	}
}

// TestPkgClientOnlyInProbes asserts that esops-go/pkg/client is imported
// only from internal/probes/. The probe layer is the single greppable
// cluster-touch boundary; this test fails as soon as another package
// introduces a pkg/client import. pkg/cluster construction also lives
// in internal/probes/ (probes.Connect) so the same constraint covers it.
func TestPkgClientOnlyInProbes(t *testing.T) {
	allowed := map[string]struct{}{
		"internal/probes": {},
	}
	watched := []string{
		"github.com/esops-dev/esops-go/pkg/client",
		"github.com/esops-dev/esops-go/pkg/cluster",
	}

	hits, err := scanDoctorImports(func(importPath string) string {
		for _, w := range watched {
			if importPath == w {
				return importPath
			}
		}
		return ""
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var bad []string
	for _, h := range hits {
		// h is "<rel-path>:<line>: <category>"; the rel path tells us
		// which package the import lives in. Allow when the directory
		// is under one of the allowed package roots.
		path := strings.SplitN(h, ":", 2)[0]
		ok := false
		for prefix := range allowed {
			if strings.HasPrefix(path, prefix+"/") || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
				ok = true
				break
			}
		}
		if !ok {
			bad = append(bad, h)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("pkg/client (or pkg/cluster) imported outside internal/probes/:\n  %s\nkeep cluster construction and capability access within probes",
			strings.Join(bad, "\n  "))
	}
}

// scanDoctorImports walks every non-test .go file under internal/ and
// cmd/, parses each, and yields one "<rel-path>:<line>: <category>"
// hit per import whose path makes match return a non-empty category.
// _test.go files are skipped so test-only imports (testify, fakes, etc.)
// don't trip the rule.
func scanDoctorImports(match func(importPath string) string) ([]string, error) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	modRoot := strings.TrimSpace(string(out))

	fset := token.NewFileSet()
	var hits []string

	for _, sub := range []string{"internal", "cmd"} {
		root := filepath.Join(modRoot, sub)
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
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			for _, imp := range f.Imports {
				ip := strings.Trim(imp.Path.Value, `"`)
				if cat := match(ip); cat != "" {
					rel, _ := filepath.Rel(modRoot, path)
					pos := fset.Position(imp.Pos())
					hits = append(hits, fmt.Sprintf("%s:%d: %s", rel, pos.Line, cat))
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", sub, err)
		}
	}
	return hits, nil
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
	"IndexRollover":             "mutating capability",
	"IndexShrinker":             "mutating capability",
	"IndexSettingsUpdater":      "mutating capability",
	"IndexTemplateUpdater":      "mutating capability",
	"AliasUpdater":              "mutating capability",
	"SnapshotCreator":           "mutating capability",
	"SnapshotVerifier":          "mutating capability (writes temp blobs to repo)",
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
