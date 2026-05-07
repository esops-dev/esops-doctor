package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/esops-dev/esops-doctor/internal/engine"
	"github.com/esops-dev/esops-doctor/internal/findings"
)

// TestMultiHTMLTableOfContents guards the per-cluster jump links: when
// a fleet has more than one cluster the page renders a TOC with anchor
// links to each section's `id="cluster-N"`, and each TOC entry carries
// the right at-a-glance badge (severity counts, "clean", "unreachable").
func TestMultiHTMLTableOfContents(t *testing.T) {
	dirty := failResult("a", "x", findings.SeverityCritical, "live failure")
	clusters := []ClusterReport{
		{
			Label:   "prod-eu",
			Header:  Header{ClusterName: "prod-eu", Dialect: "elasticsearch"},
			Results: []engine.RuleResult{dirty},
		},
		{
			Label:   "prod-us",
			Header:  Header{ClusterName: "prod-us", Dialect: "elasticsearch"},
			Results: []engine.RuleResult{{RuleID: "p", Status: engine.RuleStatusPass}},
		},
		{
			Label:             "prod-asia",
			Header:            Header{ClusterName: "prod-asia"},
			ConnectError:      "dial tcp: i/o timeout",
			ConnectErrorClass: "unreachable",
		},
	}
	var buf bytes.Buffer
	if err := MultiHTML(&buf, clusters, Options{}); err != nil {
		t.Fatalf("MultiHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`<nav class="toc"`,
		`href="#cluster-0">prod-eu`,
		`href="#cluster-1">prod-us`,
		`href="#cluster-2">prod-asia`,
		`id="cluster-0"`,
		`id="cluster-1"`,
		`id="cluster-2"`,
		`class="toc-tag critical">1 crit`,
		`class="toc-tag pass">clean`,
		`class="toc-tag errored">unreachable`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster html missing %q\nfull output (truncated):\n%.1500s", want, out)
		}
	}
}

// TestMultiHTMLNoTOCForSingleCluster keeps the TOC out of one-target
// scans — a single-item list of links is just noise. A `--targets prod-eu`
// run still goes through the multi-cluster renderer; this guards that
// the page stays clean in that case.
func TestMultiHTMLNoTOCForSingleCluster(t *testing.T) {
	clusters := []ClusterReport{{
		Label:   "prod-eu",
		Header:  Header{ClusterName: "prod-eu", Dialect: "elasticsearch"},
		Results: []engine.RuleResult{{RuleID: "p", Status: engine.RuleStatusPass}},
	}}
	var buf bytes.Buffer
	if err := MultiHTML(&buf, clusters, Options{}); err != nil {
		t.Fatalf("MultiHTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, `<nav class="toc"`) {
		t.Errorf("single-cluster fleet should not render a TOC; got:\n%.500s", out)
	}
	if !strings.Contains(out, `id="cluster-0"`) {
		t.Errorf("section anchor should still be present even without TOC; got:\n%.500s", out)
	}
}

// TestMultiHTMLSurfacesWaiverNotes guards that the multi-cluster HTML
// page renders waiver justifications inline beneath the message — the
// same shape the single-cluster html.tmpl uses. Active waivers display
// the "until" date when present; expired waivers display "expired on"
// in the error color so the rotted suppression is visible at a glance.
func TestMultiHTMLSurfacesWaiverNotes(t *testing.T) {
	exp := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	live := failResult("live_rule", "x", findings.SeverityCritical, "live failure")
	waived := failResult("waived_rule", "x", findings.SeverityCritical, "waived failure")
	waived.Finding.Suppression = &findings.Suppression{
		Justification: "ticket TC-42",
		ExpiresAt:     &exp,
		Expired:       false,
	}
	expiredAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rotted := failResult("rotted_rule", "x", findings.SeverityCritical, "rotted failure")
	rotted.Finding.Suppression = &findings.Suppression{
		Justification: "stale ticket",
		ExpiresAt:     &expiredAt,
		Expired:       true,
	}

	clusters := []ClusterReport{{
		Label:   "prod-eu",
		Header:  Header{ClusterName: "prod-eu", Dialect: "elasticsearch"},
		Results: []engine.RuleResult{live, waived, rotted},
	}}
	var buf bytes.Buffer
	if err := MultiHTML(&buf, clusters, Options{}); err != nil {
		t.Fatalf("MultiHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`class="waiver-note">waived until 2099-01-01: ticket TC-42`,
		`class="waiver-note expired">waiver expired on 2020-01-01: stale ticket`,
		`class="status waived"`, // active waiver flips display status
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster html missing %q\nfull output (truncated):\n%.1200s", want, out)
		}
	}
}

// TestMultiHTMLSurfacesScanMetadata guards that the multi-cluster HTML
// page renders fleet- and per-cluster scan metadata (started-at and
// total/per-cluster duration) so a saved report stays interpretable
// long after the run. The fleet line shows the earliest start across
// clusters; per-cluster meta shows that cluster's start.
func TestMultiHTMLSurfacesScanMetadata(t *testing.T) {
	start := time.Date(2026, 5, 7, 12, 34, 56, 0, time.UTC)
	clusters := []ClusterReport{{
		Label: "prod-eu",
		Header: Header{
			ClusterName: "prod-eu",
			Dialect:     "elasticsearch",
			StartedAt:   start,
			Duration:    1234 * time.Millisecond,
		},
		Results: []engine.RuleResult{
			{RuleID: "passes", Status: engine.RuleStatusPass},
		},
	}}
	var buf bytes.Buffer
	if err := MultiHTML(&buf, clusters, Options{}); err != nil {
		t.Fatalf("MultiHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"started 2026-05-07T12:34:56Z",
		"took 1234 ms",
		"scan started 2026-05-07T12:34:56Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster html missing %q\nfull output (truncated):\n%.800s", want, out)
		}
	}
}

// TestMultiJSONFleetScanBlock asserts the FleetDocument carries a
// top-level scan block with the earliest started_at and the total
// (sequential) duration so JSON consumers can attribute the run to a
// scan window without parsing per-cluster timestamps.
func TestMultiJSONFleetScanBlock(t *testing.T) {
	start1 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	start2 := start1.Add(2 * time.Second)
	clusters := []ClusterReport{
		{
			Label:   "prod-eu",
			Header:  Header{ClusterName: "prod-eu", Dialect: "elasticsearch", StartedAt: start1, Duration: 500 * time.Millisecond},
			Results: []engine.RuleResult{{RuleID: "passes", Status: engine.RuleStatusPass}},
		},
		{
			Label:   "prod-us",
			Header:  Header{ClusterName: "prod-us", Dialect: "elasticsearch", StartedAt: start2, Duration: 700 * time.Millisecond},
			Results: []engine.RuleResult{{RuleID: "passes", Status: engine.RuleStatusPass}},
		},
	}
	var buf bytes.Buffer
	if err := MultiJSON(&buf, clusters, Options{}); err != nil {
		t.Fatalf("MultiJSON: %v", err)
	}
	var got struct {
		Scan struct {
			StartedAt  string `json:"started_at"`
			DurationMs int64  `json:"duration_ms"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, buf.String())
	}
	if got.Scan.StartedAt != "2026-05-07T12:00:00Z" {
		t.Errorf("fleet started_at = %q, want earliest cluster start", got.Scan.StartedAt)
	}
	if got.Scan.DurationMs != 1200 {
		t.Errorf("fleet duration_ms = %d, want sum of per-cluster durations (1200)", got.Scan.DurationMs)
	}
}

// TestMultiHTMLSurfacesRemediation guards that the multi-cluster HTML
// page (used by --targets) renders the per-rule remediation column —
// the operator command, esops_commands list, and docs link — alongside
// the existing message/severity/status fields.
func TestMultiHTMLSurfacesRemediation(t *testing.T) {
	r := failResult("cluster_health_status", "hygiene", findings.SeverityWarn, "Cluster health is not green.")
	r.Finding.Remediation = findings.Remediation{
		Command:       "Check /_cluster/health",
		DocURL:        "https://example.invalid/health",
		EsopsCommands: []string{"esops ops health", "esops ops shards"},
	}
	clusters := []ClusterReport{{
		Label:   "prod-eu",
		Header:  Header{ClusterName: "prod-eu", Dialect: "elasticsearch"},
		Results: []engine.RuleResult{r},
	}}

	var buf bytes.Buffer
	if err := MultiHTML(&buf, clusters, Options{}); err != nil {
		t.Fatalf("MultiHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<th>Remediation</th>",
		"<code>Check /_cluster/health</code>",
		`class="esops-commands"`,
		`<code class="esops">esops ops health</code>`,
		`<code class="esops">esops ops shards</code>`,
		`href="https://example.invalid/health"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster html missing %q\nfull output (truncated):\n%.800s", want, out)
		}
	}
}
