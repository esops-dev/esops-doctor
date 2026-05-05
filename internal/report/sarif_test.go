package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// decodeSarif parses the rendered bytes into a generic map. The
// renderer's struct shape is private; tests assert against the wire
// JSON so a struct rename can't accidentally break the wire contract.
func decodeSarif(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("decode sarif: %v\n%s", err, b)
	}
	return d
}

func TestSARIFShape(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	d := decodeSarif(t, buf.Bytes())

	if d["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", d["version"])
	}
	if _, ok := d["$schema"].(string); !ok {
		t.Errorf("missing $schema key")
	}

	runs, _ := d["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs length = %d, want 1", len(runs))
	}
	run := runs[0].(map[string]any)

	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "esops-doctor" {
		t.Errorf("driver.name = %v, want esops-doctor", driver["name"])
	}
	if driver["informationUri"] == "" || driver["informationUri"] == nil {
		t.Errorf("driver.informationUri missing")
	}

	rules := driver["rules"].([]any)
	if len(rules) != 4 {
		t.Errorf("rules length = %d, want 4 (one per distinct rule)", len(rules))
	}
	// The failing rule is the only one that should carry rich metadata.
	var heap map[string]any
	for _, r := range rules {
		rm := r.(map[string]any)
		if rm["id"] == "heap_size" {
			heap = rm
		}
	}
	if heap == nil {
		t.Fatal("heap_size rule not in driver.rules")
	}
	if heap["name"] != "JVM heap size" {
		t.Errorf("heap_size rule.name = %v", heap["name"])
	}
	if heap["helpUri"] != "https://example.invalid/heap" {
		t.Errorf("heap_size rule.helpUri = %v", heap["helpUri"])
	}
	defaults := heap["defaultConfiguration"].(map[string]any)
	if defaults["level"] != "error" {
		t.Errorf("critical severity should map to level=error; got %v", defaults["level"])
	}

	results := run["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("results length = %d, want 4", len(results))
	}

	byRuleID := map[string]map[string]any{}
	for _, r := range results {
		rm := r.(map[string]any)
		byRuleID[rm["ruleId"].(string)] = rm
	}

	fail := byRuleID["heap_size"]
	if fail["kind"] != "fail" || fail["level"] != "error" {
		t.Errorf("fail row kind/level = %v/%v", fail["kind"], fail["level"])
	}
	if msg := fail["message"].(map[string]any); msg["text"] != "Heap misconfigured on 2 nodes." {
		t.Errorf("fail message = %v", msg)
	}

	skip := byRuleID["ilm_policy"]
	if skip["kind"] != "notApplicable" {
		t.Errorf("skipped row kind = %v, want notApplicable", skip["kind"])
	}

	errRow := byRuleID["broken"]
	if errRow["kind"] != "review" {
		t.Errorf("errored row kind = %v, want review", errRow["kind"])
	}
	if errRow["level"] != "error" {
		t.Errorf("errored row level = %v, want error", errRow["level"])
	}

	pass := byRuleID["passes"]
	if pass["kind"] != "pass" {
		t.Errorf("pass row kind = %v, want pass", pass["kind"])
	}

	// Invocations carry executionSuccessful: anyErrored should flip it.
	invocs := run["invocations"].([]any)
	if len(invocs) != 1 || invocs[0].(map[string]any)["executionSuccessful"] != false {
		t.Errorf("expected executionSuccessful=false on results with an errored rule; got %v", invocs)
	}
}

// TestSARIFSummaryOnlyDropsResults asserts --summary-only produces a
// well-formed SARIF document that names the tool and rules but
// carries zero per-result entries — useful for "scan ran, here's what
// rules existed, no findings to surface".
func TestSARIFSummaryOnlyDropsResults(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleHeader(), sampleResults(), Options{SummaryOnly: true}); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	d := decodeSarif(t, buf.Bytes())
	run := d["runs"].([]any)[0].(map[string]any)
	if r, ok := run["results"].([]any); !ok || len(r) != 0 {
		t.Errorf("--summary-only should produce empty results; got %v", run["results"])
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) == 0 {
		t.Errorf("--summary-only should still emit driver.rules")
	}
}

// TestSARIFQuietDropsPassAndSkipped: under --quiet the results array
// keeps fail+error and drops pass+skipped, matching the contract
// other formats honour.
func TestSARIFQuietDropsPassAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleHeader(), sampleResults(), Options{Quiet: true}); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	d := decodeSarif(t, buf.Bytes())
	results := d["runs"].([]any)[0].(map[string]any)["results"].([]any)
	kinds := map[string]int{}
	for _, r := range results {
		k, _ := r.(map[string]any)["kind"].(string)
		kinds[k]++
	}
	if kinds["pass"] != 0 || kinds["notApplicable"] != 0 {
		t.Errorf("--quiet should drop pass+notApplicable; got %+v", kinds)
	}
	if kinds["fail"] != 1 || kinds["review"] != 1 {
		t.Errorf("--quiet must keep fail+review (errored); got %+v", kinds)
	}
}

// TestSARIFSeverityMapping covers the four-level collapse —
// info→note, warn→warning, error→error, critical→error. SARIF doesn't
// have a "critical" level, so it must collapse to "error" without
// silently dropping anything.
func TestSARIFSeverityMapping(t *testing.T) {
	cases := []struct {
		in   engine.RuleResult
		want string
	}{
		{failResult("info_rule", "x", findings.SeverityInfo, "msg"), "note"},
		{failResult("warn_rule", "x", findings.SeverityWarn, "msg"), "warning"},
		{failResult("error_rule", "x", findings.SeverityError, "msg"), "error"},
		{failResult("crit_rule", "x", findings.SeverityCritical, "msg"), "error"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := SARIF(&buf, Header{Dialect: "elasticsearch"}, []engine.RuleResult{c.in}, Options{}); err != nil {
			t.Fatalf("SARIF: %v", err)
		}
		d := decodeSarif(t, buf.Bytes())
		results := d["runs"].([]any)[0].(map[string]any)["results"].([]any)
		got, _ := results[0].(map[string]any)["level"].(string)
		if got != c.want {
			t.Errorf("severity %v: level = %q, want %q", c.in.Finding.Severity, got, c.want)
		}
	}
}

// TestSARIFEnrichesNonFailingRules guards that the rules array carries
// metadata for every rule, not just the ones that fired. A clean scan
// is the worst case here — passing rules used to collapse to a bare
// {id} entry, which made the SARIF rule catalog unusable.
func TestSARIFEnrichesNonFailingRules(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	d := decodeSarif(t, buf.Bytes())
	rules := d["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)

	byID := map[string]map[string]any{}
	for _, r := range rules {
		rm := r.(map[string]any)
		byID[rm["id"].(string)] = rm
	}

	pass := byID["passes"]
	if pass["name"] != "Always passes" {
		t.Errorf("passing rule should carry name from r.Rule; got %v", pass["name"])
	}
	if pass["defaultConfiguration"] == nil {
		t.Errorf("passing rule should carry defaultConfiguration with severity-derived level; got %v", pass)
	}

	skip := byID["ilm_policy"]
	if skip["name"] != "ILM policy presence" {
		t.Errorf("skipped rule should carry name; got %v", skip["name"])
	}

	heap := byID["heap_size"]
	if heap["fullDescription"] == nil {
		t.Errorf("rule with description should emit fullDescription; got %v", heap)
	}
	if fd, ok := heap["fullDescription"].(map[string]any); ok {
		if !strings.Contains(fd["text"].(string), "Heap should be") {
			t.Errorf("fullDescription should carry the rule's description; got %v", fd)
		}
	}
}

// TestSARIFEmptyResults guards the zero-finding case: a clean scan
// should still produce a valid SARIF doc that downstream code-scanning
// will accept as "no findings". Specifically: results array must be
// present (not omitted) and empty.
func TestSARIFEmptyResults(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, Header{Dialect: "elasticsearch"}, nil, Options{}); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("zero-finding scan should emit empty results array; got:\n%s", out)
	}
}
