package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// Minimal doctor-JSON baselines used by the diff tests. The shape
// must match what baseline.Load can parse — keep the schema version
// and field names aligned with the loader contract.
const diffBaselineOld = `{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "cluster": {"name": "prod", "dialect": "elasticsearch", "version": "9.0.0"},
  "scan": {"started_at": "2026-05-11T10:00:00Z", "duration_ms": 100, "rule_count": 1},
  "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 0, "error": 0, "warn": 1, "info": 0}},
  "results": [
    {"rule_id": "zone_awareness", "status": "fail", "severity": "warn", "message": "Allocation awareness not configured."}
  ]
}`

const diffBaselineNewWithAdd = `{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "cluster": {"name": "prod", "dialect": "elasticsearch", "version": "9.0.0"},
  "scan": {"started_at": "2026-05-11T11:00:00Z", "duration_ms": 100, "rule_count": 2},
  "summary": {"passed": 0, "failed": 2, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 1, "error": 0, "warn": 1, "info": 0}},
  "results": [
    {"rule_id": "zone_awareness", "status": "fail", "severity": "warn", "message": "Allocation awareness not configured."},
    {"rule_id": "heap_size", "status": "fail", "severity": "critical", "message": "Heap size misconfigured."}
  ]
}`

func writeDiffBaseline(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	return path
}

func TestDiffWrongArgCountIsUsageError(t *testing.T) {
	err := newRoot().Run(context.Background(), []string{"esops-doctor", "diff", "only-one.json"})
	if err == nil {
		t.Fatal("expected usage error for single arg")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}

func TestDiffMissingFileIsUsageError(t *testing.T) {
	old := writeDiffBaseline(t, diffBaselineOld)
	err := newRoot().Run(context.Background(), []string{
		"esops-doctor", "diff", old, "/nonexistent/path/to/nothing.json",
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}

func TestDiffNoChangesExits0(t *testing.T) {
	path := writeDiffBaseline(t, diffBaselineOld)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	// Pass the same file as OLD and NEW — identical baselines must
	// be a no-op, exit 0.
	if err := root.Run(context.Background(), []string{"esops-doctor", "diff", path, path}); err != nil {
		t.Fatalf("identical baselines should exit 0; got: %v", err)
	}
	if !strings.Contains(stdout.String(), "no changes") {
		t.Errorf("expected 'no changes' marker, got: %q", stdout.String())
	}
}

func TestDiffAddedFindingTripsFailGate(t *testing.T) {
	oldPath := writeDiffBaseline(t, diffBaselineOld)
	newPath := writeDiffBaseline(t, diffBaselineNewWithAdd)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{"esops-doctor", "diff", oldPath, newPath})
	if err == nil {
		t.Fatal("expected ErrFindings for added finding")
	}
	if !errors.Is(err, exit.ErrFindings) {
		t.Errorf("err is not ErrFindings: %v", err)
	}
	if !strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("table should mention the added rule:\n%s", stdout.String())
	}
}

func TestDiffJSONOutput(t *testing.T) {
	oldPath := writeDiffBaseline(t, diffBaselineOld)
	newPath := writeDiffBaseline(t, diffBaselineNewWithAdd)
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	// Regression makes diff exit 20; we want to inspect the JSON
	// regardless, so swallow the expected ErrFindings.
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "diff", "--output", "json", oldPath, newPath,
	}); err != nil && !errors.Is(err, exit.ErrFindings) {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Summary       struct {
			Added int `json:"added"`
		} `json:"summary"`
		Added []struct {
			RuleID string `json:"rule_id"`
		} `json:"added"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schema_version=%d, want 1", doc.SchemaVersion)
	}
	if doc.Summary.Added != 1 || len(doc.Added) != 1 {
		t.Errorf("expected 1 added; got summary=%d, list=%d", doc.Summary.Added, len(doc.Added))
	}
	if len(doc.Added) > 0 && doc.Added[0].RuleID != "heap_size" {
		t.Errorf("added[0].rule_id = %q, want heap_size", doc.Added[0].RuleID)
	}
}

func TestDiffRejectsUnsupportedFormat(t *testing.T) {
	old := writeDiffBaseline(t, diffBaselineOld)
	new := writeDiffBaseline(t, diffBaselineOld)
	// Go through the package-level Run so wrapUsageError fires —
	// urfave's flag-validator path uses %v (not %w) when wrapping the
	// validator's return, so errors.Is on the raw newRoot().Run error
	// won't walk through to the inner usageError. wrapUsageError
	// re-wraps it as exit.Usage based on the message prefix, which is
	// what the binary's main does too.
	err := Run(context.Background(), []string{
		"esops-doctor", "diff", "--output", "sarif", old, new,
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err is not ErrUsage: %v", err)
	}
}
