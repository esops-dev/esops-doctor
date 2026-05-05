package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
	"github.com/esops-dev/esops-doctor/internal/rules"
)

// decodeJSON is a small helper so each test asserts against a parsed
// value rather than substring-matching the rendered bytes — substring
// matches happily pass when the field is in the wrong block.
func decodeJSON(t *testing.T, b []byte) Document {
	t.Helper()
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("decode: %v\n%s", err, b)
	}
	return d
}

func sampleResults() []engine.RuleResult {
	return []engine.RuleResult{
		{
			RuleID: "heap_size",
			Rule: rules.Rule{
				ID:          "heap_size",
				Name:        "JVM heap size",
				Category:    "resource_sanity",
				Severity:    findings.SeverityCritical,
				Description: "Heap should be ~50% of RAM and ≤31GB.",
				Probe:       "node_stats",
				Dialects:    []string{"elasticsearch", "opensearch"},
				Tags:        []string{"prod", "performance"},
				Remediation: findings.Remediation{
					Command: "Update JVM options",
					DocURL:  "https://example.invalid/heap",
				},
			},
			Status:   engine.RuleStatusFail,
			Duration: 12 * time.Millisecond,
			Finding: &findings.Finding{
				RuleID:   "heap_size",
				Name:     "JVM heap size",
				Severity: findings.SeverityCritical,
				Category: "resource_sanity",
				Message:  "Heap misconfigured on 2 nodes.",
				Dialect:  "elasticsearch",
				Remediation: findings.Remediation{
					Command: "Update JVM options",
					DocURL:  "https://example.invalid/heap",
				},
			},
		},
		{
			RuleID: "ilm_policy",
			Rule: rules.Rule{
				ID:       "ilm_policy",
				Name:     "ILM policy presence",
				Category: "lifecycle",
				Severity: findings.SeverityWarn,
				Probe:    "ilm_state",
				Dialects: []string{"elasticsearch"},
			},
			Status:     engine.RuleStatusSkipped,
			Duration:   1 * time.Millisecond,
			SkipReason: `rule does not support dialect "opensearch"`,
		},
		{
			RuleID: "broken",
			Rule: rules.Rule{
				ID:       "broken",
				Name:     "Broken rule",
				Category: "hygiene",
				Severity: findings.SeverityError,
				Probe:    "nodes",
				Dialects: []string{"elasticsearch", "opensearch"},
			},
			Status:   engine.RuleStatusError,
			Duration: 5 * time.Millisecond,
			Err:      errors.New("evaluating: no such key: jvm"),
		},
		{
			RuleID: "passes",
			Rule: rules.Rule{
				ID:       "passes",
				Name:     "Always passes",
				Category: "hygiene",
				Severity: findings.SeverityInfo,
				Probe:    "nodes",
				Dialects: []string{"elasticsearch", "opensearch"},
			},
			Status:   engine.RuleStatusPass,
			Duration: 3 * time.Millisecond,
		},
	}
}

func sampleHeader() Header {
	return Header{
		ClusterName: "prod-eu",
		Dialect:     "elasticsearch",
		Version:     "9.0.0",
		Duration:    87 * time.Millisecond,
	}
}

func TestJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	d := decodeJSON(t, buf.Bytes())

	if d.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", d.SchemaVersion, SchemaVersion)
	}
	if d.Cluster.Name != "prod-eu" || d.Cluster.Dialect != "elasticsearch" || d.Cluster.Version != "9.0.0" {
		t.Errorf("cluster block = %+v", d.Cluster)
	}
	if d.Scan.DurationMs != 87 || d.Scan.RuleCount != 4 {
		t.Errorf("scan block = %+v", d.Scan)
	}
	if d.Summary.Passed != 1 || d.Summary.Failed != 1 || d.Summary.Skipped != 1 || d.Summary.Errored != 1 {
		t.Errorf("summary counts = %+v", d.Summary)
	}
	if d.Summary.BySeverity.Critical != 1 || d.Summary.BySeverity.Error != 0 {
		t.Errorf("summary.by_severity = %+v", d.Summary.BySeverity)
	}
	if len(d.Results) != 4 {
		t.Fatalf("results length = %d, want 4", len(d.Results))
	}

	byID := map[string]Result{}
	for _, r := range d.Results {
		byID[r.RuleID] = r
	}

	fail := byID["heap_size"]
	if fail.Status != "fail" || fail.Severity != "critical" || fail.Category != "resource_sanity" {
		t.Errorf("fail row = %+v", fail)
	}
	if fail.Remediation == nil || fail.Remediation.Command == "" || fail.Remediation.DocURL == "" {
		t.Errorf("fail row should carry remediation; got %+v", fail.Remediation)
	}
	skip := byID["ilm_policy"]
	if skip.Status != "skipped" || !strings.Contains(skip.SkipReason, "opensearch") {
		t.Errorf("skipped row = %+v", skip)
	}
	errRow := byID["broken"]
	if errRow.Status != "error" || !strings.Contains(errRow.Error, "no such key: jvm") {
		t.Errorf("errored row = %+v", errRow)
	}
	pass := byID["passes"]
	// Pass rows are no longer "bare" — rule metadata (name/category/
	// severity/probe/dialects/tags) is populated for every status so a
	// downstream sees what was checked even when nothing fired.
	if pass.Status != "pass" {
		t.Errorf("pass row status = %q, want pass", pass.Status)
	}
	if pass.Name != "Always passes" || pass.Category != "hygiene" || pass.Severity != "info" {
		t.Errorf("pass row should carry rule metadata; got %+v", pass)
	}
	if pass.Probe != "nodes" {
		t.Errorf("pass row probe = %q, want nodes", pass.Probe)
	}
	if pass.Message != "" || pass.Remediation != nil {
		t.Errorf("pass row should not carry finding-only fields; got message=%q remediation=%v", pass.Message, pass.Remediation)
	}
}

// TestJSONToolBlock asserts the tool identity block is populated from
// the report Header. Without this block a downstream that ingests
// reports from multiple builds can't attribute a finding to a
// specific tool version.
func TestJSONToolBlock(t *testing.T) {
	h := sampleHeader()
	h.ToolName = "esops-doctor"
	h.ToolVersion = "0.1.0"
	h.ToolCommit = "abc123"
	h.ToolEsopsModule = "v0.0.7"
	var buf bytes.Buffer
	if err := JSON(&buf, h, sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	d := decodeJSON(t, buf.Bytes())
	if d.Tool.Name != "esops-doctor" || d.Tool.Version != "0.1.0" {
		t.Errorf("tool block = %+v", d.Tool)
	}
	if d.Tool.Commit != "abc123" || d.Tool.EsopsModule != "v0.0.7" {
		t.Errorf("tool block missing build metadata; got %+v", d.Tool)
	}
}

// TestJSONClusterPosture covers the cluster_health-derived fields the
// cli stuffs into the Header before rendering. Empty values must omit
// from the wire (so a partial-fetch cluster doesn't produce noisy
// `health: ""` rows), populated values must round-trip.
func TestJSONClusterPosture(t *testing.T) {
	h := sampleHeader()
	h.Health = "green"
	h.NodeCount = 5
	h.DataNodeCount = 3
	var buf bytes.Buffer
	if err := JSON(&buf, h, sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	d := decodeJSON(t, buf.Bytes())
	if d.Cluster.Health != "green" || d.Cluster.NodeCount != 5 || d.Cluster.DataNodeCount != 3 {
		t.Errorf("cluster posture = %+v", d.Cluster)
	}

	// Header without posture fields → posture fields elided.
	buf.Reset()
	if err := JSON(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.Contains(buf.String(), `"health"`) {
		t.Errorf("zero-valued health should be omitempty; got:\n%s", buf.String())
	}
}

// TestJSONScanStartedAt asserts the RFC3339 UTC timestamp lands in
// scan.started_at when the Header carries one, and is omitted when
// the Header doesn't.
func TestJSONScanStartedAt(t *testing.T) {
	h := sampleHeader()
	h.StartedAt = time.Date(2026, 5, 5, 18, 42, 11, 0, time.UTC)
	var buf bytes.Buffer
	if err := JSON(&buf, h, sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	d := decodeJSON(t, buf.Bytes())
	if d.Scan.StartedAt != "2026-05-05T18:42:11Z" {
		t.Errorf("scan.started_at = %q, want RFC3339 UTC", d.Scan.StartedAt)
	}

	buf.Reset()
	if err := JSON(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.Contains(buf.String(), "started_at") {
		t.Errorf("zero StartedAt should be omitempty; got:\n%s", buf.String())
	}
}

// TestJSONSummaryOnlyDropsResults asserts --summary-only suppresses the
// per-rule rows but keeps the counts intact — matches the contract
// described on Options.
func TestJSONSummaryOnlyDropsResults(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleHeader(), sampleResults(), Options{SummaryOnly: true}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	d := decodeJSON(t, buf.Bytes())
	if len(d.Results) != 0 {
		t.Errorf("--summary-only should drop results; got %d", len(d.Results))
	}
	if d.Summary.Passed != 1 || d.Summary.Failed != 1 || d.Summary.Skipped != 1 || d.Summary.Errored != 1 {
		t.Errorf("summary counts must survive --summary-only; got %+v", d.Summary)
	}
}

// TestJSONQuietDropsPassAndSkipped asserts --quiet drops pass/skip rows
// but failing and errored rows survive — those are the ones an
// operator must see. Counts always reflect the full result set.
func TestJSONQuietDropsPassAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleHeader(), sampleResults(), Options{Quiet: true}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	d := decodeJSON(t, buf.Bytes())
	statuses := map[string]int{}
	for _, r := range d.Results {
		statuses[r.Status]++
	}
	if statuses["pass"] != 0 || statuses["skipped"] != 0 {
		t.Errorf("--quiet should drop pass+skipped; got %+v", statuses)
	}
	if statuses["fail"] != 1 || statuses["error"] != 1 {
		t.Errorf("--quiet must keep fail+error rows; got %+v", statuses)
	}
	if d.Summary.Passed != 1 || d.Summary.Skipped != 1 {
		t.Errorf("summary counts must reflect full set even under --quiet; got %+v", d.Summary)
	}
}

// TestJSONOmitsEmptyOptionalFields guards the omitempty tags on the
// status-conditional fields. Without these, downstream filters on
// `severity` would have to special-case empty strings instead of
// trusting the field's presence. Asserts on a parsed map of the row
// rather than substring-matching the rendered bytes — a substring
// like `"error"` collides with `summary.by_severity.error`.
func TestJSONOmitsEmptyOptionalFields(t *testing.T) {
	results := []engine.RuleResult{{RuleID: "passes", Status: engine.RuleStatusPass}}
	var buf bytes.Buffer
	if err := JSON(&buf, Header{Dialect: "elasticsearch"}, results, Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var raw struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if len(raw.Results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(raw.Results))
	}
	row := raw.Results[0]
	for _, banned := range []string{"severity", "category", "name", "message", "dialect", "remediation", "skip_reason", "error"} {
		if _, ok := row[banned]; ok {
			t.Errorf("pass row should omit %q; got %+v", banned, row)
		}
	}
	for _, want := range []string{"rule_id", "status", "duration_ms"} {
		if _, ok := row[want]; !ok {
			t.Errorf("pass row should include %q; got %+v", want, row)
		}
	}
}

// TestJSONIsValidJSON guards against accidental rune-escape regressions
// (SetEscapeHTML(false)) — a URL with `&` in it must round-trip cleanly.
func TestJSONIsValidJSON(t *testing.T) {
	results := []engine.RuleResult{{
		RuleID: "x",
		Status: engine.RuleStatusFail,
		Finding: &findings.Finding{
			RuleID:   "x",
			Severity: findings.SeverityWarn,
			Message:  "see <docs> & options",
			Remediation: findings.Remediation{
				DocURL: "https://example.invalid/?a=1&b=2",
			},
		},
	}}
	var buf bytes.Buffer
	if err := JSON(&buf, Header{Dialect: "elasticsearch"}, results, Options{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(buf.String(), "<docs> & options") {
		t.Errorf("HTML-escaping should be off; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "a=1&b=2") {
		t.Errorf("URL ampersand should round-trip unescaped; got:\n%s", buf.String())
	}
}
