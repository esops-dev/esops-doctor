package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// failingNodeStats returns a single node whose JVM heap is twice the
// safe ceiling, so the embedded heap_size rule fires critical.
func failingNodeStats() *fakeNodeStatsInspector {
	const gb = int64(1024 * 1024 * 1024)
	return &fakeNodeStatsInspector{Result: []types.NodeStats{{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}}}
}

// TestScanBaselineSuppressesPreexisting verifies the headline M12
// contract: a finding present in --baseline does not trip --fail-on.
// Heap is misconfigured; without the baseline the run exits 20.
// With a baseline that carries heap_size as a known failure, the
// run exits 0 and the finding renders under "baselined".
func TestScanBaselineSuppressesPreexisting(t *testing.T) {
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: failingNodeStats(),
	})

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "cluster": {"name": "prod-eu", "dialect": "elasticsearch", "version": "9.0.0"},
  "scan": {"duration_ms": 1, "rule_count": 1},
  "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 1, "error": 0, "warn": 0, "info": 0}},
  "results": [
    {"rule_id": "heap_size", "status": "fail", "severity": "critical", "message": "heap rotted"}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--url", "http://example.invalid",
		"--baseline", baselinePath,
	})
	if err != nil {
		t.Fatalf("scan with baseline should exit 0; got %v (code=%d)", err, exit.Code(err))
	}
	out := stdout.String()
	if !strings.Contains(out, "baselined") {
		t.Errorf("output should mention the baselined section; got:\n%s", out)
	}
	if !strings.Contains(out, "heap_size") {
		t.Errorf("output should still list heap_size in the baselined block; got:\n%s", out)
	}
}

// TestScanBaselineMissingFingerprintFails asserts the inverse: a
// baseline that doesn't carry the failing fingerprint must NOT
// suppress it. The fail-on gate still fires and exit 20 stands.
func TestScanBaselineMissingFingerprintFails(t *testing.T) {
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: failingNodeStats(),
	})

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": 1,
  "tool": {"name": "esops-doctor", "version": "test"},
  "cluster": {"name": "prod-eu", "dialect": "elasticsearch"},
  "scan": {"duration_ms": 1, "rule_count": 1},
  "summary": {"passed": 0, "failed": 1, "skipped": 0, "errored": 0, "waived": 0, "baselined": 0, "by_severity": {"critical": 0, "error": 0, "warn": 1, "info": 0}},
  "results": [
    {"rule_id": "zone_awareness", "status": "fail", "severity": "warn"}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--url", "http://example.invalid",
		"--baseline", baselinePath,
	})
	if err == nil {
		t.Fatal("expected exit 20 — baseline does not carry heap_size")
	}
	if got := exit.Code(err); got != 20 {
		t.Errorf("exit code = %d, want 20; err=%v", got, err)
	}
}

func TestScanBaselineMissingFileExitsUsage(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--url", "http://example.invalid",
		"--baseline", "/no/such/baseline.json",
	})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", got, err)
	}
}

// TestDiffCommandReportsAddedAndResolved verifies the diff subcommand
// renders a regression-vs-old report and exits 20 when the new file
// introduces a finding the old one did not have.
func TestDiffCommandReportsAddedAndResolved(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	mustWriteBaseline(t, oldPath, []resultRow{
		{ID: "heap_size", Severity: "critical"},
		{ID: "zone_awareness", Severity: "warn"},
	})
	mustWriteBaseline(t, newPath, []resultRow{
		{ID: "heap_size", Severity: "critical"},
		{ID: "ilm_policy", Severity: "error"},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "diff", oldPath, newPath,
	})
	if err == nil {
		t.Fatal("expected exit 20 for diff with regressions")
	}
	if got := exit.Code(err); got != 20 {
		t.Errorf("exit code = %d, want 20; err=%v", got, err)
	}
	out := stdout.String()
	for _, want := range []string{"added (1)", "resolved (1)", "ilm_policy", "zone_awareness"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDiffCommandNoChangesExitsZero(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	mustWriteBaseline(t, oldPath, []resultRow{
		{ID: "heap_size", Severity: "critical"},
	})
	mustWriteBaseline(t, newPath, []resultRow{
		{ID: "heap_size", Severity: "critical"},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "diff", oldPath, newPath,
	}); err != nil {
		t.Fatalf("expected exit 0, got %v", err)
	}
	if !strings.Contains(stdout.String(), "no changes") {
		t.Errorf("expected 'no changes' summary; got:\n%s", stdout.String())
	}
}

func TestDiffCommandJSONOutputShape(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	mustWriteBaseline(t, oldPath, []resultRow{
		{ID: "heap_size", Severity: "critical"},
	})
	mustWriteBaseline(t, newPath, []resultRow{
		{ID: "heap_size", Severity: "critical"},
		{ID: "ilm_policy", Severity: "error"},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "diff", "--output", "json", oldPath, newPath,
	})
	if err == nil {
		t.Fatal("expected exit 20 (regression)")
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
		t.Errorf("schema_version = %d, want 1", doc.SchemaVersion)
	}
	if doc.Summary.Added != 1 || len(doc.Added) != 1 || doc.Added[0].RuleID != "ilm_policy" {
		t.Errorf("unexpected diff json: %+v", doc)
	}
}

func TestDiffCommandRejectsBadArgs(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "diff", "only-one.json"})
	if err == nil {
		t.Fatal("expected usage error")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", got, err)
	}
}

type resultRow struct {
	ID       string
	Severity string
}

func mustWriteBaseline(t *testing.T, path string, rows []resultRow) {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(`{"schema_version":1,"tool":{"name":"esops-doctor","version":"test"},`)
	b.WriteString(`"cluster":{"dialect":"elasticsearch"},`)
	b.WriteString(`"scan":{"duration_ms":1,"rule_count":` + itoa(len(rows)) + `},`)
	b.WriteString(`"summary":{"passed":0,"failed":` + itoa(len(rows)) + `,"skipped":0,"errored":0,"waived":0,"baselined":0,"by_severity":{"critical":0,"error":0,"warn":0,"info":0}},`)
	b.WriteString(`"results":[`)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"rule_id":"` + r.ID + `","status":"fail","severity":"` + r.Severity + `","message":"x"}`)
	}
	b.WriteString(`]}`)
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
