package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

const sampleJSONBaseline = `{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "cluster": {"name": "prod-eu", "dialect": "elasticsearch", "version": "9.0.0"},
  "scan": {"started_at": "2026-05-11T10:00:00Z", "duration_ms": 100, "rule_count": 2},
  "summary": {"passed": 0, "failed": 2, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 1, "error": 0, "warn": 1, "info": 0}},
  "results": [
    {"rule_id": "heap_size", "status": "fail", "severity": "critical", "message": "Heap size misconfigured."},
    {"rule_id": "zone_awareness", "status": "fail", "severity": "warn", "message": "Allocation awareness not configured."},
    {"rule_id": "ilm_policy", "status": "pass", "severity": "warn"}
  ]
}`

const sampleSARIFBaseline = `{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {
      "name": "esops-doctor",
      "version": "test",
      "properties": {"dialect": "elasticsearch"},
      "rules": []
    }},
    "results": [
      {"ruleId": "heap_size", "kind": "fail", "level": "error", "message": {"text": "Heap size misconfigured."}, "partialFingerprints": {"rule_id": "heap_size", "dialect": "elasticsearch"}},
      {"ruleId": "ilm_policy", "kind": "pass", "message": {"text": "Rule ilm_policy passed."}}
    ]
  }]
}`

func TestLoadJSONHarvestsFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(sampleJSONBaseline), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Format() != "json" {
		t.Errorf("format = %q, want json", set.Format())
	}
	if got := set.Len(); got != 2 {
		t.Errorf("entry count = %d, want 2 (passes must be ignored)", got)
	}
	if !set.Contains(Fingerprint{RuleID: "heap_size", Dialect: "elasticsearch"}) {
		t.Errorf("heap_size/elasticsearch fingerprint missing")
	}
	if set.Contains(Fingerprint{RuleID: "ilm_policy", Dialect: "elasticsearch"}) {
		t.Errorf("ilm_policy was a pass; should not be in baseline")
	}
	e, ok := set.Get(Fingerprint{RuleID: "heap_size", Dialect: "elasticsearch"})
	if !ok {
		t.Fatal("Get returned !ok")
	}
	if e.Severity != findings.SeverityCritical {
		t.Errorf("severity = %v, want critical", e.Severity)
	}
}

func TestLoadSARIFHarvestsFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.sarif")
	if err := os.WriteFile(path, []byte(sampleSARIFBaseline), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Format() != "sarif" {
		t.Errorf("format = %q, want sarif", set.Format())
	}
	if got := set.Len(); got != 1 {
		t.Errorf("entry count = %d, want 1", got)
	}
	if !set.Contains(Fingerprint{RuleID: "heap_size", Dialect: "elasticsearch"}) {
		t.Errorf("heap_size/elasticsearch fingerprint missing")
	}
}

func TestLoadDetectsFormatByContents(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"sarif-by-schema", sampleSARIFBaseline, "sarif"},
		{"doctor-json-by-schema-version", sampleJSONBaseline, "json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, c.name+".bin") // misleading extension
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			set, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if set.Format() != c.want {
				t.Errorf("format = %q, want %q", set.Format(), c.want)
			}
		})
	}
}

func TestLoadRejectsEmptyOrBogus(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"empty", "", "empty"},
		{"not-json", "hello", "JSON object"},
		{"unknown-shape", `{"hello": "world"}`, "not a doctor JSON document"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, c.name+".json")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/baseline.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file") {
		// Wrapped via %w, so errors.Is(err, fs.ErrNotExist) should hold.
		t.Errorf("err = %v; should wrap fs.ErrNotExist", err)
	}
}

func TestApplyMatchesFingerprintAndReportsDrift(t *testing.T) {
	set := NewSet([]Entry{
		{
			Fingerprint: Fingerprint{RuleID: "heap_size", Dialect: "elasticsearch"},
			Severity:    findings.SeverityCritical,
			Message:     "heap rotted",
		},
		{
			Fingerprint: Fingerprint{RuleID: "retired_rule", Dialect: "elasticsearch"},
			Severity:    findings.SeverityWarn,
		},
		{
			Fingerprint: Fingerprint{RuleID: "fix_me", Dialect: "elasticsearch"},
			Severity:    findings.SeverityError,
		},
	}, "test.json", "json")

	results := []engine.RuleResult{
		{
			RuleID:  "heap_size",
			Rule:    rules.Rule{ID: "heap_size"},
			Status:  engine.RuleStatusFail,
			Finding: &findings.Finding{RuleID: "heap_size", Dialect: "elasticsearch", Severity: findings.SeverityCritical},
		},
		{
			RuleID:  "new_finding",
			Rule:    rules.Rule{ID: "new_finding"},
			Status:  engine.RuleStatusFail,
			Finding: &findings.Finding{RuleID: "new_finding", Dialect: "elasticsearch", Severity: findings.SeverityError},
		},
		{
			RuleID: "fix_me",
			Rule:   rules.Rule{ID: "fix_me"},
			Status: engine.RuleStatusPass,
		},
	}

	catalog := map[string]bool{
		"heap_size":   true,
		"new_finding": true,
		"fix_me":      true,
	}
	drift := set.Apply(results, catalog)

	// heap_size should be flagged as baselined.
	if results[0].Finding.Baseline == nil {
		t.Errorf("expected heap_size to carry Baseline marker")
	}
	if results[0].Finding.Baseline.Source != "test.json" {
		t.Errorf("baseline source = %q", results[0].Finding.Baseline.Source)
	}
	// new_finding (not in baseline) should be untouched.
	if results[1].Finding.Baseline != nil {
		t.Errorf("new_finding should not be marked baselined")
	}

	// drift: retired_rule (unknown to catalog), fix_me (passed in current scan).
	reasons := map[string]DriftReason{}
	for _, d := range drift {
		reasons[d.Entry.Fingerprint.RuleID] = d.Reason
	}
	if reasons["retired_rule"] != DriftRuleUnknown {
		t.Errorf("retired_rule drift reason = %v, want %v", reasons["retired_rule"], DriftRuleUnknown)
	}
	if reasons["fix_me"] != DriftDidNotFire {
		t.Errorf("fix_me drift reason = %v, want %v", reasons["fix_me"], DriftDidNotFire)
	}
}

func TestApplyMatchesDialectAgnosticBaseline(t *testing.T) {
	// A SARIF baseline written by an older doctor (or a sister tool)
	// has no dialect property. Match should still hit for any
	// rule_id-matching current finding regardless of dialect.
	set := NewSet([]Entry{
		{Fingerprint: Fingerprint{RuleID: "heap_size"}},
	}, "old.sarif", "sarif")

	results := []engine.RuleResult{
		{
			RuleID:  "heap_size",
			Status:  engine.RuleStatusFail,
			Finding: &findings.Finding{RuleID: "heap_size", Dialect: "elasticsearch", Severity: findings.SeverityCritical},
		},
	}
	set.Apply(results, nil)
	if results[0].Finding.Baseline == nil {
		t.Errorf("dialect-agnostic baseline should still match heap_size")
	}
}

func TestCompareSetDifferences(t *testing.T) {
	old := NewSet([]Entry{
		{Fingerprint: Fingerprint{RuleID: "a", Dialect: "elasticsearch"}, Severity: findings.SeverityError},
		{Fingerprint: Fingerprint{RuleID: "b", Dialect: "elasticsearch"}, Severity: findings.SeverityWarn},
	}, "old.json", "json")
	newSet := NewSet([]Entry{
		{Fingerprint: Fingerprint{RuleID: "b", Dialect: "elasticsearch"}, Severity: findings.SeverityCritical},
		{Fingerprint: Fingerprint{RuleID: "c", Dialect: "elasticsearch"}, Severity: findings.SeverityInfo},
	}, "new.json", "json")

	d := Compare(old, newSet)

	if len(d.Added) != 1 || d.Added[0].Fingerprint.RuleID != "c" {
		t.Errorf("added = %+v, want one entry for c", d.Added)
	}
	if len(d.Resolved) != 1 || d.Resolved[0].Fingerprint.RuleID != "a" {
		t.Errorf("resolved = %+v, want one entry for a", d.Resolved)
	}
	if len(d.SeverityChanged) != 1 {
		t.Errorf("severity_changed = %+v, want one entry", d.SeverityChanged)
	}
	if d.SeverityChanged[0].Old.Severity != findings.SeverityWarn ||
		d.SeverityChanged[0].New.Severity != findings.SeverityCritical {
		t.Errorf("severity change = %+v", d.SeverityChanged[0])
	}
}

// TestLoadSARIFMultiClusterPerRunDialect verifies the SARIF
// multi-run shape: each run carries its own
// tool.driver.properties.dialect and partialFingerprints, and the
// loader harvests them per run rather than collapsing across runs.
func TestLoadSARIFMultiClusterPerRunDialect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.sarif")
	const fleet = `{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "esops-doctor", "version": "t", "properties": {"dialect": "elasticsearch"}, "rules": []}},
      "results": [
        {"ruleId": "heap_size", "kind": "fail", "level": "error", "message": {"text": "x"}, "partialFingerprints": {"rule_id": "heap_size", "dialect": "elasticsearch"}}
      ]
    },
    {
      "tool": {"driver": {"name": "esops-doctor", "version": "t", "properties": {"dialect": "opensearch"}, "rules": []}},
      "results": [
        {"ruleId": "ilm_policy", "kind": "fail", "level": "error", "message": {"text": "y"}, "partialFingerprints": {"rule_id": "ilm_policy", "dialect": "opensearch"}}
      ]
    }
  ]
}`
	if err := os.WriteFile(path, []byte(fleet), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := set.Len(); got != 2 {
		t.Errorf("entry count = %d, want 2", got)
	}
	if !set.Contains(Fingerprint{RuleID: "heap_size", Dialect: "elasticsearch"}) ||
		!set.Contains(Fingerprint{RuleID: "ilm_policy", Dialect: "opensearch"}) {
		t.Errorf("dialect-scoped fingerprints missing: %v", set.Entries())
	}
}

// TestLoadJSONMultiClusterHarvestsAllRuns guards the shape the
// FleetDocument writer emits: results live under
// clusters[].document.results, not clusters[].results. A regression
// here means multi-cluster baselines silently match nothing.
func TestLoadJSONMultiClusterHarvestsAllRuns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.json")
	const fleet = `{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "scan": {"started_at": "2026-05-11T10:00:00Z", "duration_ms": 100},
  "fleet": {"clusters_total": 2, "clusters_scanned": 2, "clusters_unreachable": 0, "passed": 0, "failed": 2, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 1, "error": 1, "warn": 0, "info": 0}},
  "clusters": [
    {
      "label": "prod-eu",
      "document": {
        "schema_version": 1,
        "tool": {"name": "esops-doctor", "version": "test"},
        "cluster": {"dialect": "elasticsearch"},
        "scan": {"duration_ms": 50, "rule_count": 1},
        "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 1, "error": 0, "warn": 0, "info": 0}},
        "results": [
          {"rule_id": "heap_size", "status": "fail", "severity": "critical"}
        ]
      }
    },
    {
      "label": "prod-us",
      "document": {
        "schema_version": 1,
        "tool": {"name": "esops-doctor", "version": "test"},
        "cluster": {"dialect": "opensearch"},
        "scan": {"duration_ms": 50, "rule_count": 1},
        "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 0, "error": 1, "warn": 0, "info": 0}},
        "results": [
          {"rule_id": "ilm_policy", "status": "fail", "severity": "error"}
        ]
      }
    },
    {
      "label": "prod-ap",
      "connect_error": "unreachable",
      "connect_error_class": "unreachable"
    }
  ]
}`
	if err := os.WriteFile(path, []byte(fleet), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := set.Len(); got != 2 {
		t.Errorf("entry count = %d, want 2 (one per scanned cluster; connect-failed clusters skipped)", got)
	}
	if !set.Contains(Fingerprint{RuleID: "heap_size", Dialect: "elasticsearch"}) {
		t.Errorf("missing heap_size/elasticsearch entry")
	}
	if !set.Contains(Fingerprint{RuleID: "ilm_policy", Dialect: "opensearch"}) {
		t.Errorf("missing ilm_policy/opensearch entry — dialect is read per-cluster, not from the fleet")
	}
}

func TestCompareIgnoresSarifCriticalErrorCollapse(t *testing.T) {
	// A baseline round-tripped through SARIF reads critical back as
	// error. Compare must not surface this as a severity change.
	old := NewSet([]Entry{
		{Fingerprint: Fingerprint{RuleID: "x", Dialect: "elasticsearch"}, Severity: findings.SeverityError},
	}, "old.sarif", "sarif")
	newSet := NewSet([]Entry{
		{Fingerprint: Fingerprint{RuleID: "x", Dialect: "elasticsearch"}, Severity: findings.SeverityCritical},
	}, "new.json", "json")
	d := Compare(old, newSet)
	if len(d.SeverityChanged) != 0 {
		t.Errorf("critical↔error collapse should not be reported; got %+v", d.SeverityChanged)
	}
}
