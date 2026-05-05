package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/esops-dev/esops-doctor/internal/findings"
)

// goodRule returns a YAML body that would pass Validate. Used as a
// baseline; tests that exercise specific failure modes mutate it.
const goodRule = `
checks:
  - id: example_rule
    name: Example
    category: example
    severity: warn
    description: Example rule used in tests.
    probe: nodes
    condition: "size(self) > 0"
    message: example
    dialects: [elasticsearch, opensearch]
`

func TestLoadFSReadsYAMLAndSetsSource(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/cat-a/one.yaml": {Data: []byte(goodRule)},
	}
	cat, err := LoadFS(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(cat.Rules) != 1 {
		t.Fatalf("Rules = %d, want 1", len(cat.Rules))
	}
	r := cat.Rules[0]
	if r.ID != "example_rule" {
		t.Errorf("ID = %q, want example_rule", r.ID)
	}
	if r.Severity != findings.SeverityWarn {
		t.Errorf("Severity = %v, want SeverityWarn", r.Severity)
	}
	if r.Source != "rules/cat-a/one.yaml" {
		t.Errorf("Source = %q, want rules/cat-a/one.yaml", r.Source)
	}
}

func TestLoadFSSkipsNonYAMLAndDotfiles(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/cat-a/one.yaml":  {Data: []byte(goodRule)},
		"rules/cat-a/notes.txt": {Data: []byte("ignore me")},
		"rules/cat-a/.gitkeep":  {Data: []byte("")},
		"rules/cat-b/two.yml":   {Data: []byte("checks: []")}, // .yml not .yaml — out of scope
	}
	cat, err := LoadFS(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(cat.Rules) != 1 {
		t.Errorf("Rules = %d, want 1 (only .yaml files count)", len(cat.Rules))
	}
}

func TestLoadFSSortsByID(t *testing.T) {
	const second = `
checks:
  - id: bbb
    name: B
    category: x
    severity: info
    description: d
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`
	const first = `
checks:
  - id: aaa
    name: A
    category: x
    severity: info
    description: d
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`
	// Files sorted "z-first.yaml" before "a-second.yaml" to ensure
	// rule order isn't accidentally driven by file-walk order.
	fsys := fstest.MapFS{
		"rules/z-first.yaml":  {Data: []byte(first)},
		"rules/a-second.yaml": {Data: []byte(second)},
	}
	cat, err := LoadFS(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if cat.Rules[0].ID != "aaa" || cat.Rules[1].ID != "bbb" {
		t.Errorf("rules not sorted by ID: %v", []string{cat.Rules[0].ID, cat.Rules[1].ID})
	}
}

func TestLoadFSReturnsParseErrorWithPath(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/broken.yaml": {Data: []byte("checks: [\n  - id: x: oops\n")},
	}
	_, err := LoadFS(fsys, "rules")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "rules/broken.yaml") {
		t.Errorf("error should mention path; got %v", err)
	}
}

func TestLoadDirRejectsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "x.yaml")
	if err := os.WriteFile(file, []byte(goodRule), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(file)
	if err == nil {
		t.Fatal("expected error pointing LoadDir at a file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error should explain why; got %v", err)
	}
}

func TestLoadDirRejectsMissing(t *testing.T) {
	_, err := LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestLoadDirRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), []byte(goodRule), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(cat.Rules) != 1 {
		t.Errorf("Rules = %d, want 1", len(cat.Rules))
	}
}

func TestAppendMergesAndResorts(t *testing.T) {
	a := &Catalog{Rules: []Rule{{ID: "aaa"}, {ID: "ccc"}}}
	b := &Catalog{Rules: []Rule{{ID: "bbb"}}}
	a.Append(b)
	got := []string{a.Rules[0].ID, a.Rules[1].ID, a.Rules[2].ID}
	want := []string{"aaa", "bbb", "ccc"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("after Append, ID order = %v, want %v", got, want)
			break
		}
	}
}

func TestAppendNilIsSafe(t *testing.T) {
	a := &Catalog{Rules: []Rule{{ID: "aaa"}}}
	a.Append(nil)
	if len(a.Rules) != 1 {
		t.Errorf("Append(nil) changed rules: %v", a.Rules)
	}
}

// TestEmbeddedCatalogValidates is the load-bearing check that the
// shipped catalog will not break a release build. It also exercises
// the //go:embed wiring through the top-level esopsdoctor package.
func TestEmbeddedCatalogValidates(t *testing.T) {
	cat, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(cat.Rules) == 0 {
		t.Fatal("LoadEmbedded returned no rules; embed wiring broken or rules/ empty")
	}
	if issues := cat.Validate(); len(issues) > 0 {
		var msgs []string
		for _, i := range issues {
			msgs = append(msgs, i.Error())
		}
		t.Fatalf("embedded catalog failed validation:\n  %s", strings.Join(msgs, "\n  "))
	}
}
