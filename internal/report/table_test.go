package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

func failResult(id, category string, sev findings.Severity, msg string) engine.RuleResult {
	return engine.RuleResult{
		RuleID: id,
		Status: engine.RuleStatusFail,
		Finding: &findings.Finding{
			RuleID:   id,
			Name:     id,
			Severity: sev,
			Category: category,
			Message:  msg,
		},
	}
}

func TestTableEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "elasticsearch"}, nil, TableOptions{}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no findings against elasticsearch") {
		t.Errorf("expected empty-result hint; got %q", out)
	}
	if !strings.Contains(out, "summary:") {
		t.Errorf("expected summary footer; got %q", out)
	}
}

func TestTableLinesUpFindingsAndSummary(t *testing.T) {
	results := []engine.RuleResult{
		failResult("heap_size", "resource_sanity", findings.SeverityCritical, "Heap size misconfigured on 2 nodes."),
		failResult("zone_awareness", "resource_sanity", findings.SeverityWarn, "Allocation awareness not configured."),
		{RuleID: "passes", Status: engine.RuleStatusPass},
	}
	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "opensearch"}, results, TableOptions{}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SEVERITY", "RULE", "CATEGORY", "MESSAGE",
		"critical", "heap_size", "Heap size misconfigured",
		"warn", "zone_awareness",
		"summary: 1 critical, 0 error, 1 warn, 0 info; 1 passed, 0 skipped, 0 errored, 0 waived | dialect=opensearch",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestTableSurfacesSkippedReasons(t *testing.T) {
	// CLAUDE.md §3: Skipped is reported (not silent) so an operator
	// sees that a rule was inapplicable rather than absent.
	results := []engine.RuleResult{
		{RuleID: "ilm_policy", Status: engine.RuleStatusSkipped, SkipReason: "rule does not support dialect \"opensearch\""},
		{RuleID: "tls_only_audit", Status: engine.RuleStatusSkipped, SkipReason: "probe \"security_audit\" not registered"},
	}
	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "opensearch"}, results, TableOptions{}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "skipped (2)") {
		t.Errorf("expected skipped-section header; got %q", out)
	}
	if !strings.Contains(out, "ilm_policy") || !strings.Contains(out, "rule does not support dialect") {
		t.Errorf("expected skipped row with reason; got %q", out)
	}
}

func TestTableQuietSuppressesSkipped(t *testing.T) {
	// --quiet drops the skipped/passed sections but keeps any actual
	// failing rows visible — those are the ones an operator must see.
	results := []engine.RuleResult{
		failResult("heap_size", "resource_sanity", findings.SeverityCritical, "msg"),
		{RuleID: "ilm_policy", Status: engine.RuleStatusSkipped, SkipReason: "dialect mismatch"},
	}
	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "elasticsearch"}, results, TableOptions{Quiet: true}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "skipped (") {
		t.Errorf("--quiet should hide skipped section header; got %q", out)
	}
	if strings.Contains(out, "ilm_policy") {
		t.Errorf("--quiet should hide skipped rule rows; got %q", out)
	}
	if !strings.Contains(out, "heap_size") {
		t.Errorf("--quiet must still show failing rows; got %q", out)
	}
	if !strings.Contains(out, "1 skipped") {
		t.Errorf("--quiet should still surface skipped count in summary; got %q", out)
	}
}

func TestTableSummaryOnly(t *testing.T) {
	results := []engine.RuleResult{
		failResult("heap_size", "resource_sanity", findings.SeverityCritical, "msg"),
		{RuleID: "skipped_rule", Status: engine.RuleStatusSkipped, SkipReason: "x"},
		{RuleID: "errored_rule", Status: engine.RuleStatusError, Err: errors.New("boom")},
	}
	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "elasticsearch"}, results, TableOptions{SummaryOnly: true}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "SEVERITY") || strings.Contains(out, "skipped_rule") || strings.Contains(out, "errored_rule") {
		t.Errorf("--summary-only should suppress per-rule sections; got %q", out)
	}
	if !strings.Contains(out, "summary: 1 critical") {
		t.Errorf("summary should still print; got %q", out)
	}
}

func TestTableErrorsSection(t *testing.T) {
	results := []engine.RuleResult{
		{RuleID: "broken", Status: engine.RuleStatusError, Err: errors.New("evaluating: no such key: jvm")},
	}
	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "elasticsearch"}, results, TableOptions{}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "errors (1)") || !strings.Contains(out, "broken") {
		t.Errorf("expected errors section; got %q", out)
	}
	if !strings.Contains(out, "no such key: jvm") {
		t.Errorf("error message should appear; got %q", out)
	}
	if !strings.Contains(out, "1 errored") {
		t.Errorf("summary should count errors; got %q", out)
	}
}

func TestMaxFailingSeverity(t *testing.T) {
	cases := []struct {
		name    string
		results []engine.RuleResult
		want    findings.Severity
	}{
		{"none", nil, findings.SeverityUnknown},
		{"only passes/skipped", []engine.RuleResult{
			{Status: engine.RuleStatusPass},
			{Status: engine.RuleStatusSkipped},
		}, findings.SeverityUnknown},
		{"single warn", []engine.RuleResult{
			failResult("a", "x", findings.SeverityWarn, "m"),
		}, findings.SeverityWarn},
		{"warn and critical", []engine.RuleResult{
			failResult("a", "x", findings.SeverityWarn, "m"),
			failResult("b", "x", findings.SeverityCritical, "m"),
			failResult("c", "x", findings.SeverityError, "m"),
		}, findings.SeverityCritical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MaxFailingSeverity(c.results); got != c.want {
				t.Errorf("MaxFailingSeverity = %v, want %v", got, c.want)
			}
		})
	}
}

func TestFormatHeaderShapes(t *testing.T) {
	cases := []struct {
		name string
		h    Header
		want string
	}{
		{"dialect only", Header{Dialect: "elasticsearch"}, "dialect=elasticsearch"},
		{"cluster + dialect", Header{Dialect: "elasticsearch", ClusterName: "prod-eu"}, `cluster="prod-eu" (elasticsearch)`},
		{"cluster + version", Header{Dialect: "opensearch", ClusterName: "stg", Version: "2.18.0"}, `cluster="stg" (opensearch 2.18.0)`},
		{"with duration ms", Header{Dialect: "elasticsearch", Duration: 12 * time.Millisecond}, "dialect=elasticsearch, took 12ms"},
		{"with duration s", Header{Dialect: "elasticsearch", Duration: 1500 * time.Millisecond}, "dialect=elasticsearch, took 1.50s"},
		{"empty", Header{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := formatHeader(c.h); got != c.want {
				t.Errorf("formatHeader(%+v) = %q, want %q", c.h, got, c.want)
			}
		})
	}
}

func TestOneLineCollapsesNewlinesAndTabs(t *testing.T) {
	got := oneLine("first\nsecond\twith\ttabs")
	if got != "first | second with tabs" {
		t.Errorf("oneLine = %q", got)
	}
}

// TestActiveWaiverDropsFromSeverityCountsAndMax confirms the
// suppression-aware accounting: an active waiver lifts its finding out
// of MaxFailingSeverity (so the --fail-on gate in the cli passes) and
// out of the per-severity totals (so the summary line tells the truth).
func TestActiveWaiverDropsFromSeverityCountsAndMax(t *testing.T) {
	live := failResult("a", "x", findings.SeverityCritical, "live")
	waived := failResult("b", "x", findings.SeverityCritical, "waived")
	waived.Finding.Suppression = &findings.Suppression{Justification: "ok"}

	results := []engine.RuleResult{live, waived}

	if got := MaxFailingSeverity(results); got != findings.SeverityCritical {
		t.Errorf("MaxFailingSeverity should still be critical from live; got %v", got)
	}

	// Drop the live one; only the waived critical remains. Now max
	// should be SeverityUnknown so the cli won't fire ErrFindings.
	results = []engine.RuleResult{waived}
	if got := MaxFailingSeverity(results); got != findings.SeverityUnknown {
		t.Errorf("MaxFailingSeverity over-only-waivers should be Unknown; got %v", got)
	}

	c := classify(results)
	if c.critical != 0 {
		t.Errorf("active waiver should not appear as critical; got %+v", c)
	}
	if c.waived != 1 {
		t.Errorf("waived count = %d, want 1", c.waived)
	}
}

// TestExpiredWaiverStaysLoud locks in the CLAUDE.md §9 guarantee:
// the finding contributes to severity counts and the --fail-on max
// even when the operator's waiver matched, because the waiver expired.
func TestExpiredWaiverStaysLoud(t *testing.T) {
	exp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	r := failResult("a", "x", findings.SeverityError, "[waiver expired 2024-01-01] orig msg")
	r.Finding.Suppression = &findings.Suppression{
		Justification: "stale",
		ExpiresAt:     &exp,
		Expired:       true,
	}

	results := []engine.RuleResult{r}
	if got := MaxFailingSeverity(results); got != findings.SeverityError {
		t.Errorf("expired waiver should keep severity live; got %v", got)
	}
	c := classify(results)
	if c.error != 1 || c.waived != 0 {
		t.Errorf("expired waiver counts wrong: %+v", c)
	}
}

// TestTableSurfacesWaivedSection confirms the renderer splits live
// failures from active-waiver suppressions, and that the footer carries
// the waived count.
func TestTableSurfacesWaivedSection(t *testing.T) {
	exp := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	live := failResult("heap_size", "resource_sanity", findings.SeverityCritical, "live failure")
	waived := failResult("tls_transport", "security", findings.SeverityCritical, "TLS missing")
	waived.Finding.Suppression = &findings.Suppression{
		Justification: "internal-only cluster",
		ExpiresAt:     &exp,
	}

	var buf bytes.Buffer
	if err := Table(&buf, Header{Dialect: "elasticsearch"},
		[]engine.RuleResult{live, waived}, TableOptions{}); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"heap_size", "live failure",
		"waived (1):",
		"tls_transport",
		"expires 2099-01-01",
		"internal-only cluster",
		"1 waived",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
	// The waived row must NOT appear in the live failures table.
	headerIdx := strings.Index(out, "SEVERITY")
	waivedIdx := strings.Index(out, "waived (1)")
	if headerIdx == -1 || waivedIdx == -1 || headerIdx >= waivedIdx {
		t.Fatalf("expected SEVERITY header before waived section; got:\n%s", out)
	}
	// Anything between header and waived section is the live table —
	// tls_transport must not appear there.
	liveTable := out[headerIdx:waivedIdx]
	if strings.Contains(liveTable, "tls_transport") {
		t.Errorf("active waiver leaked into live findings table:\n%s", liveTable)
	}
}
