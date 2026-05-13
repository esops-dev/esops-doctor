package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// sampleScanJSON is a minimal doctor JSON document covering a single
// failed rule. Carries the rule_id explain-finding looks up plus the
// shape it consumes from the wire (severity, message, remediation).
const sampleScanJSON = `{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "cluster": {"name": "prod-eu", "dialect": "elasticsearch", "version": "9.0.0"},
  "scan": {"started_at": "2025-01-01T00:00:00Z", "duration_ms": 12, "rule_count": 1},
  "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0,
    "by_severity": {"critical": 1, "error": 0, "warn": 0, "info": 0}},
  "results": [
    {
      "rule_id": "heap_size",
      "name": "JVM heap size configuration",
      "category": "resource_sanity",
      "severity": "critical",
      "probe": "node_stats",
      "status": "fail",
      "duration_ms": 5,
      "message": "Heap size misconfigured on 2 nodes.",
      "remediation": {"command": "Update JVM options and restart nodes", "doc_url": "https://x.test/heap"},
      "fingerprint": {"rule_id": "heap_size", "dialect": "elasticsearch"}
    }
  ]
}
`

// TestExplainFindingPrintsRuleAndRuntimeContext drives the joined
// view end-to-end: read a captured scan, look up the rule in the
// embedded catalog, and print the explain block alongside the
// runtime fields.
func TestExplainFindingPrintsRuleAndRuntimeContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(path, []byte(sampleScanJSON), 0o600); err != nil {
		t.Fatalf("write scan: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "explain-finding", "--from", path, "heap_size",
	}); err != nil {
		t.Fatalf("explain-finding: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"heap_size — JVM heap size configuration",
		"severity: critical",
		"probe:    node_stats",
		"Runtime context (from --from):",
		"cluster:     prod-eu (elasticsearch 9.0.0)",
		"status:      fail",
		"message:     Heap size misconfigured on 2 nodes.",
		"fingerprint: rule_id=heap_size dialect=elasticsearch",
		"Remediation (from finding):",
		"https://x.test/heap",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain-finding output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestExplainFindingRequiresFrom confirms the --from flag is required.
// The command makes no sense without a captured scan; an operator
// looking for the static rule definition uses `explain RULE_ID`.
func TestExplainFindingRequiresFrom(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "explain-finding", "heap_size"})
	if err == nil {
		t.Fatal("expected error for missing --from")
	}
}

// TestExplainFindingMissingRuleInScan confirms a rule that is not in
// the captured scan results surfaces as a clear usage error, hinting
// at `explain RULE_ID` for the static definition.
func TestExplainFindingMissingRuleInScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(path, []byte(sampleScanJSON), 0o600); err != nil {
		t.Fatalf("write scan: %v", err)
	}

	err := Run(context.Background(), []string{
		"esops-doctor", "explain-finding", "--from", path, "not_in_scan",
	})
	if err == nil {
		t.Fatal("expected usage error for rule not in scan")
	}
	if exit.Code(err) != 2 {
		t.Errorf("exit code = %d, want 2", exit.Code(err))
	}
}

// TestExplainFindingRejectsNonJSON confirms a SARIF / random text
// file is rejected explicitly: the operator-facing trade-off is
// "use JSON for triage round-trips".
func TestExplainFindingRejectsNonJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not.json")
	if err := os.WriteFile(path, []byte("plain text"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := Run(context.Background(), []string{
		"esops-doctor", "explain-finding", "--from", path, "heap_size",
	})
	if err == nil {
		t.Fatal("expected usage error for non-JSON input")
	}
}

// fleetScanJSON is a minimal fleet (multi-cluster) JSON document.
// Two clusters; heap_size fires on one of them. Lets the test exercise
// both the auto-pick path (only one cluster carries the finding) and
// the --target disambiguation when both do.
const fleetScanJSON = `{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "scan": {"started_at": "2025-01-01T00:00:00Z", "duration_ms": 25},
  "fleet": {"clusters_total": 2, "clusters_scanned": 2, "clusters_unreachable": 0,
    "passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0,
    "by_severity": {"critical": 1, "error": 0, "warn": 0, "info": 0}},
  "clusters": [
    {
      "label": "prod-eu",
      "document": {
        "schema_version": 1,
        "cluster": {"name": "prod-eu", "dialect": "elasticsearch", "version": "9.0.0"},
        "scan": {"duration_ms": 5, "rule_count": 1},
        "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0,
          "by_severity": {"critical": 1, "error": 0, "warn": 0, "info": 0}},
        "results": [{
          "rule_id": "heap_size",
          "name": "JVM heap size configuration",
          "category": "resource_sanity",
          "severity": "critical",
          "probe": "node_stats",
          "status": "fail",
          "duration_ms": 5,
          "message": "Heap size misconfigured on 2 nodes."
        }]
      }
    },
    {
      "label": "prod-us",
      "document": {
        "schema_version": 1,
        "cluster": {"name": "prod-us", "dialect": "elasticsearch", "version": "9.0.0"},
        "scan": {"duration_ms": 4, "rule_count": 1},
        "summary": {"passed": 1, "failed": 0, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0,
          "by_severity": {"critical": 0, "error": 0, "warn": 0, "info": 0}},
        "results": [{
          "rule_id": "heap_size",
          "name": "JVM heap size configuration",
          "category": "resource_sanity",
          "severity": "critical",
          "probe": "node_stats",
          "status": "pass",
          "duration_ms": 4
        }]
      }
    }
  ]
}
`

// TestExplainFindingFleetAutoPicksTarget — fleet JSON with the
// rule firing on a single cluster auto-resolves without --target.
// Note: heap_size is in *both* clusters' results above (one pass,
// one fail) — the auto-pick path requires the rule_id to be present
// somewhere, so this also covers "auto-pick when multiple clusters
// hit". Make a more selective test for the single-hit case below.
func TestExplainFindingFleetWithTargetResolves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.json")
	if err := os.WriteFile(path, []byte(fleetScanJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "explain-finding",
		"--from", path, "--target", "prod-eu", "heap_size",
	}); err != nil {
		t.Fatalf("explain-finding: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"heap_size — JVM heap size configuration",
		"cluster:     prod-eu",
		"status:      fail",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestExplainFindingFleetAmbiguousWithoutTarget — when the rule
// fires on multiple clusters and --target is not set, the command
// asks the operator to disambiguate.
func TestExplainFindingFleetAmbiguousWithoutTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.json")
	if err := os.WriteFile(path, []byte(fleetScanJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := Run(context.Background(), []string{
		"esops-doctor", "explain-finding", "--from", path, "heap_size",
	})
	if err == nil {
		t.Fatal("expected usage error for ambiguous fleet match")
	}
	if !strings.Contains(err.Error(), "--target") {
		t.Errorf("err should mention --target; got %v", err)
	}
	if !strings.Contains(err.Error(), "prod-eu") || !strings.Contains(err.Error(), "prod-us") {
		t.Errorf("err should list candidate targets; got %v", err)
	}
}

// TestExplainFindingFleetUnknownTarget — --target referencing a
// label that is not in the fleet document fails with the list of
// candidate labels so the operator can fix the typo.
func TestExplainFindingFleetUnknownTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fleet.json")
	if err := os.WriteFile(path, []byte(fleetScanJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := Run(context.Background(), []string{
		"esops-doctor", "explain-finding",
		"--from", path, "--target", "made-up", "heap_size",
	})
	if err == nil {
		t.Fatal("expected usage error for unknown --target")
	}
	if !strings.Contains(err.Error(), "available:") {
		t.Errorf("err should list available targets; got %v", err)
	}
}

// TestExplainFindingTargetOnSingleClusterRejected — passing --target
// against a single-cluster scan is a usage error; the flag only
// makes sense for fleet inputs.
func TestExplainFindingTargetOnSingleClusterRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(path, []byte(sampleScanJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := Run(context.Background(), []string{
		"esops-doctor", "explain-finding",
		"--from", path, "--target", "anything", "heap_size",
	})
	if err == nil {
		t.Fatal("expected usage error for --target on single-cluster scan")
	}
}
