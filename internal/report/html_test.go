package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// assertWellFormed is a cheap structural check: the document must
// start with a doctype, end with </html>, and have balanced opens and
// closes for the load-bearing block tags. Pulling in
// golang.org/x/net/html for a real parser would breach the direct-deps
// budget — html/template already guarantees per-interpolation escape
// correctness, so what's left to catch here is "did we forget to
// close a tag in html.tmpl".
func assertWellFormed(t *testing.T, b []byte) {
	t.Helper()
	s := string(b)
	if !strings.HasPrefix(strings.TrimSpace(s), "<!DOCTYPE html>") {
		t.Fatalf("document should start with DOCTYPE; got %.40q", s)
	}
	if !strings.Contains(s, "</html>") {
		t.Fatalf("document should close <html>; got tail %.40q", s[max(0, len(s)-80):])
	}
	for _, tag := range []string{"html", "head", "body", "header", "table", "tbody", "thead", "script", "style"} {
		opens := strings.Count(s, "<"+tag+">") + strings.Count(s, "<"+tag+" ")
		closes := strings.Count(s, "</"+tag+">")
		if opens != closes {
			t.Errorf("tag %q unbalanced: %d opens vs %d closes", tag, opens, closes)
		}
	}
}

func TestHTMLShape(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	assertWellFormed(t, buf.Bytes())

	for _, want := range []string{
		"<!DOCTYPE html>",
		"<title>esops-doctor scan",
		"prod-eu",
		"elasticsearch 9.0.0",
		`data-status="fail"`,
		`data-severity="critical"`,
		"heap_size",
		"resource_sanity",
		"Heap misconfigured on 2 nodes.",
		"ilm_policy",
		"opensearch", // skip reason mentions opensearch
		"broken",
		"no such key: jvm",
		`data-sort="status"`,
		`data-sort="severity"`,
		// Inline JS markers
		"applyFilters",
		"sort-asc",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestHTMLSummaryOnlyDropsResultsTable(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), sampleResults(), Options{SummaryOnly: true}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	assertWellFormed(t, buf.Bytes())
	if strings.Contains(out, `<table id="results">`) {
		t.Errorf("--summary-only should drop results table; got:\n%s", out)
	}
	if strings.Contains(out, "heap_size") {
		t.Errorf("--summary-only should drop per-rule rows; got:\n%s", out)
	}
	if !strings.Contains(out, "1 critical") {
		t.Errorf("severity counts must survive --summary-only; got:\n%s", out)
	}
}

func TestHTMLQuietDropsPassAndSkipped(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), sampleResults(), Options{Quiet: true}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	assertWellFormed(t, buf.Bytes())
	for _, banned := range []string{`data-status="pass"`, `data-status="skipped"`, "ilm_policy"} {
		if strings.Contains(out, banned) {
			t.Errorf("--quiet should drop pass+skipped row marker %q; got:\n%s", banned, out)
		}
	}
	for _, want := range []string{`data-status="fail"`, `data-status="error"`, "heap_size", "broken"} {
		if !strings.Contains(out, want) {
			t.Errorf("--quiet must keep fail+error row marker %q; got:\n%s", want, out)
		}
	}
}

// TestHTMLEscapesHostileContent guards that html/template's contextual
// escaping is in force: a rule message containing `<script>` must not
// produce executable markup, and the full hostile string must round-trip
// through escaped HTML entities.
func TestHTMLEscapesHostileContent(t *testing.T) {
	hostile := `<script>alert("pwn")</script>`
	results := []engine.RuleResult{
		failResult("xss_test", "security", findings.SeverityCritical, hostile),
	}
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), results, Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, hostile) {
		t.Errorf("hostile content should be escaped on output; got raw <script> tag")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped <script>; got:\n%s", out)
	}
}

// TestHTMLEmptyResultsRendersFallback covers the zero-finding case:
// the renderer must still produce a valid document with the empty-
// state hint, not an empty <table> whose <tbody> is hollow.
func TestHTMLEmptyResultsRendersFallback(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), nil, Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	assertWellFormed(t, buf.Bytes())
	if strings.Contains(out, `<table id="results">`) {
		t.Errorf("empty results should not render the table; got:\n%s", out)
	}
	if !strings.Contains(out, "No per-rule results") {
		t.Errorf("empty-state fallback should appear; got:\n%s", out)
	}
}

// TestHTMLSurfacesRuleMetadata guards that the row carries the new
// rule-metadata fields (name, tags, probe, description) — without
// these the HTML report visibly carried less than the JSON output
// from the same scan, which is the gap the user flagged.
func TestHTMLSurfacesRuleMetadata(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`class="rule-name">JVM heap size`,
		`class="rule-id">heap_size`,
		`class="tag">prod`,
		`class="tag">performance`,
		`probe: <code>node_stats`,
		`<details class="about"`,
		"about this rule",
		"Heap should be ~50% of RAM",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html output missing rule metadata %q\nfull output (truncated):\n%.800s", want, out)
		}
	}
}

// TestHTMLToolFooter guards the new footer with tool identity and
// scan timestamp. Empty fields elide so the footer reads cleanly even
// when ldflags didn't fill in a commit.
func TestHTMLToolFooter(t *testing.T) {
	h := sampleHeader()
	h.ToolName = "esops-doctor"
	h.ToolVersion = "0.1.0"
	h.ToolCommit = "abc123"
	h.ToolEsopsModule = "v0.0.7"
	h.StartedAt = time.Date(2026, 5, 5, 18, 42, 11, 0, time.UTC)
	var buf bytes.Buffer
	if err := HTML(&buf, h, sampleResults(), Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`<footer class="tool-footer">`,
		"esops-doctor",
		"0.1.0",
		"abc123",
		"v0.0.7",
		"2026-05-05T18:42:11Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tool footer missing %q\nfull output (truncated):\n%.800s", want, out)
		}
	}
}

// TestHTMLPassFilterAutoChecksOnCleanScan guards the UX fix for clean
// scans: when there are no fails/errors/skipped rows, the `pass`
// status filter must default to checked so a healthy cluster does
// not render an empty-looking table. On a noisy scan the filter
// stays unchecked so actionable rows surface first.
func TestHTMLPassFilterAutoChecksOnCleanScan(t *testing.T) {
	clean := []engine.RuleResult{{RuleID: "heap_size", Status: engine.RuleStatusPass}}
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), clean, Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(buf.String(), `data-filter="status" value="pass" checked`) {
		t.Errorf("clean scan should auto-check the pass filter; got:\n%s", buf.String())
	}

	noisy := sampleResults() // includes a fail, a skip, an error
	buf.Reset()
	if err := HTML(&buf, sampleHeader(), noisy, Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if strings.Contains(buf.String(), `data-filter="status" value="pass" checked`) {
		t.Errorf("noisy scan should leave pass filter unchecked; got:\n%s", buf.String())
	}
}

// TestHTMLEmptyStateHintIsPresent guards that the filter-hides-everything
// fallback element is in the markup whenever there are results — the JS
// reveals it when applyFilters() finds zero visible rows. Without this,
// the user sees a table header with no rows and no explanation.
func TestHTMLEmptyStateHintIsPresent(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), sampleResults(), Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `id="filtered-out"`) {
		t.Errorf("results page should carry the filtered-out hint element; got:\n%s", out)
	}
	if !strings.Contains(out, `id="show-all"`) {
		t.Errorf("filtered-out hint should include the Show all rules button; got:\n%s", out)
	}
}

// TestHTMLSeverityRankInTemplate guards the severity sort: the data-
// sort-value attribute must reflect the rank function so the JS click
// handler sorts by urgency rather than alphabetically. critical (4) >
// error (3) > warn (2) > info (1) > unknown (0).
func TestHTMLSeverityRankInTemplate(t *testing.T) {
	results := []engine.RuleResult{
		failResult("a", "x", findings.SeverityWarn, "m"),
		failResult("b", "x", findings.SeverityCritical, "m"),
	}
	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(), results, Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="sev critical" data-sort-value="4"`) {
		t.Errorf("critical row should carry rank 4; got:\n%s", out)
	}
	if !strings.Contains(out, `class="sev warn" data-sort-value="2"`) {
		t.Errorf("warn row should carry rank 2; got:\n%s", out)
	}
}

// TestHTMLActiveWaiverShownAsWaivedRow guards the suppression rendering
// path: the row's data-status flips to "waived" so the status filter
// works, the waived count pill appears in the header, and the
// justification rides inline as a waiver-note. Expired waivers retain
// data-status="fail" but get the expired class so an operator can spot
// the rotted suppression at a glance.
func TestHTMLActiveWaiverShownAsWaivedRow(t *testing.T) {
	exp := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	live := failResult("live", "x", findings.SeverityCritical, "live failure")
	waived := failResult("waived_rule", "x", findings.SeverityCritical, "waived failure")
	waived.Finding.Suppression = &findings.Suppression{
		Justification: "approved by SRE",
		ExpiresAt:     &exp,
	}
	expiredAt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	expired := failResult("expired_rule", "x", findings.SeverityCritical,
		"[waiver expired 2024-01-01] expired failure")
	expired.Finding.Suppression = &findings.Suppression{
		Justification: "lapsed",
		ExpiresAt:     &expiredAt,
		Expired:       true,
	}

	var buf bytes.Buffer
	if err := HTML(&buf, sampleHeader(),
		[]engine.RuleResult{live, waived, expired}, Options{}); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`class="pill waived">1 waived`,
		`data-filter="status" value="waived"`,
		`data-status="waived"`,
		`class="status waived"`,
		`approved by SRE`,
		`waiver-note expired`,
		`waiver expired on 2024-01-01: lapsed`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html waiver rendering missing %q\nfull output (truncated):\n%.1200s", want, out)
		}
	}
	// Live row stays as fail; expired row stays as fail (suppression
	// failed). Only the active waiver flips to data-status="waived".
	if strings.Count(out, `data-status="waived"`) != 1 {
		t.Errorf("expected exactly one row marked waived; got:\n%s", out)
	}
}
