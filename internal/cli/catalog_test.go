package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

func TestApplyCatalogFilterRuleID(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"prod"}},
		{ID: "b", Tags: []string{"dev"}},
		{ID: "c", Tags: []string{"prod", "perf"}},
	}}
	out, unknown := applyCatalogFilter(cat, catalogFilter{RuleIDs: []string{"a", "c"}})
	if len(out.Rules) != 2 {
		t.Fatalf("expected 2 surviving rules; got %d", len(out.Rules))
	}
	if len(unknown) != 0 {
		t.Errorf("expected no unknown selectors; got %v", unknown)
	}
}

func TestApplyCatalogFilterIncludeTags(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"prod"}},
		{ID: "b", Tags: []string{"dev"}},
		{ID: "c", Tags: []string{"prod", "perf"}},
	}}
	out, _ := applyCatalogFilter(cat, catalogFilter{IncludeTags: []string{"perf"}})
	if len(out.Rules) != 1 || out.Rules[0].ID != "c" {
		t.Errorf("expected only c; got %+v", out.Rules)
	}
}

func TestApplyCatalogFilterSkipTags(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"prod"}},
		{ID: "b", Tags: []string{"dev"}},
	}}
	out, _ := applyCatalogFilter(cat, catalogFilter{SkipTags: []string{"prod"}})
	if len(out.Rules) != 1 || out.Rules[0].ID != "b" {
		t.Errorf("expected only b; got %+v", out.Rules)
	}
}

func TestApplyCatalogFilterSkipTagsBeatsIncludeTags(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"prod", "perf"}},
		{ID: "b", Tags: []string{"prod"}},
	}}
	out, _ := applyCatalogFilter(cat,
		catalogFilter{IncludeTags: []string{"prod"}, SkipTags: []string{"perf"}})
	if len(out.Rules) != 1 || out.Rules[0].ID != "b" {
		t.Errorf("expected only b (a has perf); got %+v", out.Rules)
	}
}

func TestApplyCatalogFilterUnknownReports(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "a", Tags: []string{"prod"}},
	}}
	_, unknown := applyCatalogFilter(cat, catalogFilter{
		RuleIDs:     []string{"no_such_rule"},
		IncludeTags: []string{"phantom"},
		SkipTags:    []string{"unused"},
	})
	if len(unknown) != 3 {
		t.Errorf("expected 3 unknown selectors; got %v", unknown)
	}
}

func TestApplyCatalogFilterMatchesAlias(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{
		{ID: "canonical", DeprecatedAliases: []string{"old_name"}},
	}}
	out, unknown := applyCatalogFilter(cat, catalogFilter{RuleIDs: []string{"old_name"}})
	if len(out.Rules) != 1 {
		t.Errorf("expected canonical to survive when filter names its alias; got %+v", out.Rules)
	}
	if len(unknown) != 0 {
		t.Errorf("alias should not be reported as unknown; got %v", unknown)
	}
}

func TestApplyCatalogFilterEmptyReturnsCatalog(t *testing.T) {
	cat := &rules.Catalog{Rules: []rules.Rule{{ID: "a"}}}
	out, unknown := applyCatalogFilter(cat, catalogFilter{})
	if out != cat {
		t.Error("empty filter should short-circuit and return the input pointer")
	}
	if unknown != nil {
		t.Errorf("empty filter should not produce unknown selectors; got %v", unknown)
	}
}

func TestUserRulesDirHonorsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/x")
	got, ok := userRulesDir()
	if !ok || got != "/tmp/x/esops-doctor/rules.d" {
		t.Errorf("userRulesDir = (%q, %v); want /tmp/x/esops-doctor/rules.d", got, ok)
	}
}

func TestLoadLayeredCatalogPicksUpRulesDir(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: layered_extra
    name: Layered Extra
    category: extras
    severity: warn
    description: Picked up via --rules-dir layering.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := loadLayeredCatalog(dir)
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	found := false
	for _, r := range cat.Rules {
		if r.ID == "layered_extra" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected layered_extra rule from --rules-dir")
	}
}

func TestLoadLayeredCatalogPicksUpUserRulesDir(t *testing.T) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		t.Skip("XDG_CONFIG_HOME not set in test env")
	}
	rulesDir := filepath.Join(xdg, "esops-doctor", "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(xdg, "esops-doctor")) })
	body := []byte(`checks:
  - id: user_layered_rule
    name: User Layered
    category: extras
    severity: info
    description: Lives in the user rules.d directory.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(rulesDir, "u.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := loadLayeredCatalog("")
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	found := false
	for _, r := range cat.Rules {
		if r.ID == "user_layered_rule" {
			found = true
		}
	}
	if !found {
		t.Error("expected user_layered_rule from XDG_CONFIG_HOME/esops-doctor/rules.d")
	}
}

// TestScanFiltersOutFailingRuleByID — pair with the existing
// TestScanFailingFindingExitsTwenty: same overSized fixture, but the
// scan is narrowed to a different rule_id, so heap_size is not even
// evaluated and the exit is clean.
func TestScanFiltersOutFailingRuleByID(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	// Filter to a rule that doesn't exist in the catalog — the result is
	// zero rules to evaluate, and the scan exits clean.
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--rule-id", "no_such_rule",
		"--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan should pass when filter excludes the failing rule; got %v", err)
	}
}

func TestScanFiltersBySkipTags(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	// heap_size has tag "performance" — skipping it suppresses the rule.
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--skip-tags", "performance",
		"--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan should pass when --skip-tags excludes heap_size; got %v", err)
	}
}

func TestScanRulesDirRollsExtraRuleIntoEvaluation(t *testing.T) {
	// Drop a rule into a --rules-dir that's guaranteed to fail, then
	// confirm scan exits 20 on its finding — proves the layered
	// catalog flowed into engine.Compile + Evaluate.
	dir := t.TempDir()
	body := []byte(`checks:
  - id: always_fails
    name: Always Fails
    category: extras
    severity: critical
    description: Sentinel rule whose CEL condition is constantly false.
    probe: cluster_health
    condition: "false"
    message: sentinel always fails
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	stubConnect(t, &client.Client{
		Info:   types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		Health: &fakeClusterHealthInspector{Result: types.ClusterHealth{Status: "green"}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--rules-dir", dir,
		"--rule-id", "always_fails",
		"--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected ErrFindings from --rules-dir-supplied always_fails rule")
	}
	if !strings.Contains(stdout.String(), "always_fails") {
		t.Errorf("expected always_fails in scan output; got %q", stdout.String())
	}
}

// fakeClusterHealthInspector satisfies the cluster_health probe with a
// canned ClusterHealth value so always_fails has data to evaluate
// against. Result is the value FetchClusterHealth returns; tests can
// override Status to drive different paths.
type fakeClusterHealthInspector struct{ Result types.ClusterHealth }

func (f *fakeClusterHealthInspector) Health(context.Context) (types.ClusterHealth, error) {
	return f.Result, nil
}

// TestRulesDirOverridesEmbeddedRuleByID — drop a same-id rule with a
// different severity into --rules-dir and confirm the embedded one is
// shadowed. Scope is the catalog: the user's rule survives, the
// embedded one drops out before the validator sees the catalog (so
// the duplicate-id error does not fire).
func TestRulesDirOverridesEmbeddedRuleByID(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: heap_size
    name: Custom heap_size override
    category: resource_sanity
    severity: info
    description: Operator-supplied override for heap_size.
    probe: node_stats
    condition: "true"
    message: heap_size overridden
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "heap_size.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := loadLayeredCatalog(dir)
	if err != nil {
		t.Fatalf("loadLayeredCatalog: %v", err)
	}
	var seen int
	var got rules.Rule
	for _, r := range cat.Rules {
		if r.ID == "heap_size" {
			seen++
			got = r
		}
	}
	if seen != 1 {
		t.Fatalf("expected heap_size to appear exactly once after override; got %d", seen)
	}
	if got.Severity != findings.SeverityInfo || got.Name != "Custom heap_size override" {
		t.Errorf("expected operator-supplied heap_size; got name=%q severity=%s",
			got.Name, got.Severity)
	}
}

// TestRulesDirIntraLayerDuplicateStillErrors — within a single layer
// (the operator's --rules-dir), two rules with the same ID is a typo,
// not an override. The duplicate-id validator must still fire.
func TestRulesDirIntraLayerDuplicateStillErrors(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: dup_within_layer
    name: First copy
    category: extras
    severity: warn
    description: First copy of an intra-layer duplicate.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
  - id: dup_within_layer
    name: Second copy
    category: extras
    severity: warn
    description: Second copy of the same id in the same file.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "dup.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadLayeredCatalog(dir)
	if err == nil {
		t.Fatal("expected duplicate-id error from intra-layer duplicates")
	}
	if !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("expected duplicate-id error; got %v", err)
	}
}
