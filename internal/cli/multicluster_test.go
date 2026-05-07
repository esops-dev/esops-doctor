package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/config"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// stubConnectByURL routes Connect to a per-URL fake. Tests register a
// canned *client.Client per address so a multi-cluster scan can verify
// each target was visited and that per-cluster outputs render
// independently. Nil responses become an unreachable error so a test
// can simulate a partial fleet.
//
// The test config file (writeMultiTestConfig) maps each context name to
// a synthetic URL so this URL keying lines up with the contexts the
// caller wires up — a context resolution from the config produces the
// URL the stub matches against.
func stubConnectByURL(t *testing.T, fakes map[string]*client.Client) {
	t.Helper()
	prev := connectFn
	connectFn = func(_ context.Context, cc config.Context) (*client.Client, error) {
		key := cc.URL
		if cl, ok := fakes[key]; ok && cl != nil {
			return cl, nil
		}
		if cl, ok := fakes[key]; ok && cl == nil {
			return nil, fmt.Errorf("%w: stubbed unreachable for %s", exit.ErrUnreachable, key)
		}
		return nil, fmt.Errorf("%w: no fake registered for %s", exit.ErrUnreachable, key)
	}
	t.Cleanup(func() { connectFn = prev })
}

func gb(n int64) int64 { return n * 1024 * 1024 * 1024 }

// healthyClient builds a *client.Client configured with the minimum
// capability the embedded heap_size rule needs to pass.
func healthyClient(name string) *client.Client {
	return &client.Client{
		Info: types.ClusterInfo{
			Dialect:     types.DialectElasticsearch,
			ClusterName: name,
			Version:     "9.0.0",
		},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{{
			Name: "n1",
			JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: gb(8), MaxBytes: gb(8)}},
			OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: gb(32)},
		}}},
	}
}

// failingClient returns a client whose node stats trigger heap_size's
// failure condition (32 GiB heap on 64 GiB RAM — over the 50% / 31 GiB
// guard rails).
func failingClient(name string) *client.Client {
	return &client.Client{
		Info: types.ClusterInfo{
			Dialect:     types.DialectElasticsearch,
			ClusterName: name,
			Version:     "9.0.0",
		},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{{
			Name: "n1",
			JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: gb(32), MaxBytes: gb(32)}},
			OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: gb(64)},
		}}},
	}
}

// writeMultiTestConfig writes a tiny esops config file declaring one
// context per (name, URL) pair, mode 0o600 so the loader's
// world-readable check stays happy. Returns the path; tests pass it
// via --config so resolveMultiTargets has somewhere to look up the
// context names. protection: none keeps the loader from refusing the
// scan on safety grounds.
func writeMultiTestConfig(t *testing.T, contexts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "esops.yaml")
	var b strings.Builder
	b.WriteString("contexts:\n")
	for name, url := range contexts {
		fmt.Fprintf(&b, "  %s:\n    url: %s\n    protection: none\n", name, url)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write esops config: %v", err)
	}
	return path
}

// TestScanMultiTargetsHappyPath drives --targets ctx1,ctx2 against two
// stubbed-healthy clusters and asserts (a) both per-cluster blocks
// render in the table output and (b) the fleet summary line lands at
// the bottom with two clusters scanned.
func TestScanMultiTargetsHappyPath(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
		"http://us.invalid": healthyClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "prod-eu,prod-us",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"=== cluster 1/2: prod-eu ===",
		"=== cluster 2/2: prod-us ===",
		`cluster="eu"`,
		`cluster="us"`,
		"fleet: 2 clusters, 0 unreachable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster table missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestScanMultiTargetsAnyFailingExitsTwenty exits 20 if any one target
// trips the threshold. The other (healthy) cluster must still render
// its block — fleet visibility is the point of the multi-cluster scan.
func TestScanMultiTargetsAnyFailingExitsTwenty(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
		"http://us.invalid": failingClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "prod-eu,prod-us",
	})
	if err == nil {
		t.Fatal("expected ErrFindings on at least one failing cluster")
	}
	if got := exit.Code(err); got != 20 {
		t.Errorf("exit code = %d, want 20; err=%v", got, err)
	}
	if !strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("output should include the failing rule id; got %q", stdout.String())
	}
}

// TestScanMultiTargetsUnreachableContinues confirms an unreachable
// cluster does not abort the fleet sweep: the second (healthy)
// cluster's block still renders, and the exit code reflects the
// connect failure (3) since no findings tripped the threshold.
func TestScanMultiTargetsUnreachableContinues(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"down": "http://down.invalid",
		"up":   "http://up.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://down.invalid": nil, // synthesises ErrUnreachable
		"http://up.invalid":   healthyClient("up"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "down,up",
	})
	if err == nil {
		t.Fatal("expected the first connect failure to bubble up as exit 3")
	}
	if got := exit.Code(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (unreachable); err=%v", got, err)
	}
	out := stdout.String()
	for _, want := range []string{
		"=== cluster 1/2: down ===",
		"connect failed (unreachable)",
		"=== cluster 2/2: up ===",
		"fleet: 2 clusters, 1 unreachable",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestScanMultiTargetsFindingsBeatUnreachable asserts the documented
// exit-code priority: when one cluster trips findings and another is
// unreachable, the gate fires (exit 20) — the operator-actionable
// outcome wins over the per-cluster connect failure.
func TestScanMultiTargetsFindingsBeatUnreachable(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"down": "http://down.invalid",
		"us":   "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://down.invalid": nil,
		"http://us.invalid":   failingClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "down,us",
	})
	if err == nil {
		t.Fatal("expected ErrFindings to outrank the connect failure")
	}
	if got := exit.Code(err); got != 20 {
		t.Errorf("exit code = %d, want 20 (findings outrank unreachable); err=%v", got, err)
	}
}

// TestScanMultiTargetsMutuallyExclusiveWithURL fails fast at exit 2
// when --targets and --url are combined — picking one is the
// documented rule and a silent winner would surprise an operator.
func TestScanMultiTargetsMutuallyExclusiveWithURL(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
	})
	err := Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "prod-eu",
		"--url", "http://elsewhere.invalid",
	})
	if err == nil {
		t.Fatal("expected usage error when --targets and --url are combined")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (usage); err=%v", got, err)
	}
}

// TestScanMultiTargetsMutuallyExclusiveWithContext fails fast at exit
// 2 when --targets and --context are both set; both reference the
// config's contexts list and a silent winner would surprise an
// operator.
func TestScanMultiTargetsMutuallyExclusiveWithContext(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	err := Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--context", "prod-us",
		"--targets", "prod-eu",
	})
	if err == nil {
		t.Fatal("expected usage error when --targets and --context are combined")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (usage); err=%v", got, err)
	}
}

// TestScanMultiTargetsRejectsUnknownContext — a typo in --targets
// must surface as exit 2 before any cluster work happens. The
// context-resolution error already names the bad context, so the
// exit-code wrapping is what we're asserting here.
func TestScanMultiTargetsRejectsUnknownContext(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
	})
	err := Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "prod-eu,prdo-us", // typo
	})
	if err == nil {
		t.Fatal("expected usage error for unknown context in --targets")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (usage); err=%v", got, err)
	}
}

// TestScanMultiTargetsDeduplicates — pasting the same context twice in
// --targets is a common operator mistake; doctor scans the cluster
// once and continues rather than running it twice.
func TestScanMultiTargetsDeduplicates(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--targets", "prod-eu,prod-eu",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(stdout.String(), "fleet: 1 clusters") {
		t.Errorf("expected dedup to leave 1 cluster; got %q", stdout.String())
	}
}

// TestScanMultiJSONOutput confirms the json multi-cluster wire shape
// carries one cluster per entry plus the fleet rollup.
func TestScanMultiJSONOutput(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
		"http://us.invalid": failingClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "json",
		"--targets", "prod-eu,prod-us",
	})
	// Failing-cluster path: ErrFindings is expected.
	if err == nil || !errors.Is(err, exit.ErrFindings) {
		t.Fatalf("expected ErrFindings; got %v", err)
	}

	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Tool          struct {
			Name string `json:"name"`
		} `json:"tool"`
		Fleet struct {
			ClustersTotal       int `json:"clusters_total"`
			ClustersScanned     int `json:"clusters_scanned"`
			ClustersUnreachable int `json:"clusters_unreachable"`
			BySeverity          struct {
				Critical int `json:"critical"`
			} `json:"by_severity"`
		} `json:"fleet"`
		Clusters []struct {
			Label    string `json:"label"`
			Document *struct {
				Cluster struct {
					Name string `json:"name"`
				} `json:"cluster"`
			} `json:"document"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", doc.SchemaVersion)
	}
	if doc.Tool.Name != "esops-doctor" {
		t.Errorf("tool.name = %q", doc.Tool.Name)
	}
	if doc.Fleet.ClustersTotal != 2 || doc.Fleet.ClustersScanned != 2 {
		t.Errorf("fleet counts wrong: total=%d scanned=%d unreachable=%d",
			doc.Fleet.ClustersTotal, doc.Fleet.ClustersScanned, doc.Fleet.ClustersUnreachable)
	}
	if doc.Fleet.BySeverity.Critical < 1 {
		t.Errorf("fleet.by_severity.critical should reflect the failing-heap rule; got %d", doc.Fleet.BySeverity.Critical)
	}
	if len(doc.Clusters) != 2 {
		t.Fatalf("expected 2 cluster entries; got %d", len(doc.Clusters))
	}
}

// TestScanMultiJSONConnectErrorEntry exercises the connect-failure
// branch of buildFleetDocument: an unreachable cluster surfaces in the
// json wire shape with a non-empty connect_error and connect_error_class
// rather than as a missing entry.
func TestScanMultiJSONConnectErrorEntry(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"down": "http://down.invalid",
		"up":   "http://up.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://down.invalid": nil,
		"http://up.invalid":   healthyClient("up"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "json",
		"--targets", "down,up",
	})
	if err == nil {
		t.Fatal("expected the connect failure to bubble up as exit 3")
	}
	if got := exit.Code(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (unreachable); err=%v", got, err)
	}

	var doc struct {
		Fleet struct {
			ClustersTotal       int `json:"clusters_total"`
			ClustersScanned     int `json:"clusters_scanned"`
			ClustersUnreachable int `json:"clusters_unreachable"`
		} `json:"fleet"`
		Clusters []struct {
			Label             string `json:"label"`
			ConnectError      string `json:"connect_error"`
			ConnectErrorClass string `json:"connect_error_class"`
			Document          *struct {
				Cluster struct {
					Name string `json:"name"`
				} `json:"cluster"`
			} `json:"document"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.Fleet.ClustersUnreachable != 1 || doc.Fleet.ClustersScanned != 1 {
		t.Errorf("fleet counts wrong: total=%d scanned=%d unreachable=%d",
			doc.Fleet.ClustersTotal, doc.Fleet.ClustersScanned, doc.Fleet.ClustersUnreachable)
	}
	if len(doc.Clusters) != 2 {
		t.Fatalf("expected 2 cluster entries; got %d", len(doc.Clusters))
	}
	// First entry: down → connect_error fields populated, document nil.
	if doc.Clusters[0].ConnectError == "" {
		t.Errorf("first entry should carry connect_error; got %+v", doc.Clusters[0])
	}
	if doc.Clusters[0].ConnectErrorClass != "unreachable" {
		t.Errorf("connect_error_class = %q, want %q", doc.Clusters[0].ConnectErrorClass, "unreachable")
	}
	if doc.Clusters[0].Document != nil {
		t.Errorf("connect-failed entry should not carry a document; got %+v", doc.Clusters[0].Document)
	}
	// Second entry: up → document populated, no connect_error.
	if doc.Clusters[1].ConnectError != "" {
		t.Errorf("healthy entry should not carry connect_error; got %q", doc.Clusters[1].ConnectError)
	}
	if doc.Clusters[1].Document == nil || doc.Clusters[1].Document.Cluster.Name != "up" {
		t.Errorf("healthy entry should carry document with cluster name; got %+v", doc.Clusters[1])
	}
}

// TestScanMultiSARIFOutput confirms multi-cluster sarif emits one
// runs[] entry per cluster.
func TestScanMultiSARIFOutput(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
		"http://us.invalid": healthyClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "sarif",
		"--targets", "prod-eu,prod-us",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid sarif json: %v\n%s", err, stdout.String())
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 2 {
		t.Errorf("expected 2 runs (one per cluster); got %d", len(runs))
	}
}

// TestScanMultiJUnitOutput confirms multi-cluster junit emits one
// <testsuite> per cluster within a single <testsuites>.
func TestScanMultiJUnitOutput(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
		"http://us.invalid": healthyClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "junit",
		"--targets", "prod-eu,prod-us",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	if !strings.HasPrefix(out, `<?xml version="1.0"`) {
		t.Errorf("junit output should start with XML header; got %.40q", out)
	}
	if strings.Count(out, "<testsuite ") != 2 {
		t.Errorf("expected 2 <testsuite> blocks (one per cluster); got %d in:\n%s",
			strings.Count(out, "<testsuite "), out)
	}
}

// TestScanMultiJUnitConnectErrorEntry exercises the connect-failure
// rendering in the JUnit multi-cluster path: a per-cluster
// <testsuite> wraps a synthetic <testcase name="connect"> with an
// <error> element carrying the class and message. Pairs with the JSON
// connect-failure test so every structured format pins its
// connect-failure wire shape.
func TestScanMultiJUnitConnectErrorEntry(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"down": "http://down.invalid",
		"up":   "http://up.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://down.invalid": nil, // ErrUnreachable
		"http://up.invalid":   healthyClient("up"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "junit",
		"--targets", "down,up",
	})
	if err == nil {
		t.Fatal("expected the connect failure to bubble up as exit 3")
	}
	if got := exit.Code(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (unreachable); err=%v", got, err)
	}
	out := stdout.String()
	for _, want := range []string{
		`<testsuite name="down"`,
		`<testcase name="connect"`,
		`type="unreachable"`,
		`<testsuite name="up"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("junit connect-error output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestScanMultiSARIFConnectErrorEntry exercises the connect-failure
// rendering in the SARIF multi-cluster path: every cluster gets a
// runs[] entry, the unreachable one carries
// invocations[].executionSuccessful=false and an empty results array.
func TestScanMultiSARIFConnectErrorEntry(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"down": "http://down.invalid",
		"up":   "http://up.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://down.invalid": nil,
		"http://up.invalid":   healthyClient("up"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "sarif",
		"--targets", "down,up",
	})
	if err == nil {
		t.Fatal("expected the connect failure to bubble up as exit 3")
	}
	if got := exit.Code(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (unreachable); err=%v", got, err)
	}

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []map[string]any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results     []map[string]any `json:"results"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid sarif json: %v\n%s", err, stdout.String())
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("expected 2 runs (one per cluster); got %d", len(doc.Runs))
	}
	// First run = down: no rules, no results, executionSuccessful=false.
	if len(doc.Runs[0].Invocations) == 0 || doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Errorf("connect-failed run should carry executionSuccessful=false; got %+v", doc.Runs[0].Invocations)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("connect-failed run should have no results; got %d", len(doc.Runs[0].Results))
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("connect-failed run should have no rules; got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}
	// Second run = up: rules + results populated, execution succeeded.
	if len(doc.Runs[1].Invocations) == 0 || !doc.Runs[1].Invocations[0].ExecutionSuccessful {
		t.Errorf("healthy run should carry executionSuccessful=true; got %+v", doc.Runs[1].Invocations)
	}
	if len(doc.Runs[1].Tool.Driver.Rules) == 0 {
		t.Errorf("healthy run should carry the rule catalog; got 0 rules")
	}
}

// TestScanMultiHTMLConnectErrorEntry exercises the connect-failure
// rendering in the HTML multi-cluster page: the unreachable cluster
// surfaces as a `connect failed` block carrying the class and message,
// while the healthy one renders its results table normally.
func TestScanMultiHTMLConnectErrorEntry(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"down": "http://down.invalid",
		"up":   "http://up.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://down.invalid": nil,
		"http://up.invalid":   healthyClient("up"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "html",
		"--targets", "down,up",
	})
	if err == nil {
		t.Fatal("expected the connect failure to bubble up as exit 3")
	}
	if got := exit.Code(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (unreachable); err=%v", got, err)
	}
	out := stdout.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		`class="connect-error"`,
		"connect failed (unreachable)",
		// Healthy cluster's section should still render with its
		// per-cluster summary line (the "1 nodes" string only appears
		// when Document populated, so seeing it confirms the rest of
		// the page rendered around the failure).
		"esops-doctor fleet scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html connect-error output missing %q\nfull output (truncated):\n%.500s", want, out)
		}
	}
}

// TestScanMultiTargetsInsecureLayering asserts that --insecure layers
// onto every resolved context's TLS block when set on a multi-cluster
// scan. Doctor doesn't have a per-target TLS surface; --cacert /
// --insecure are fleet-wide overrides, and the test pins that
// behaviour so a future regression (e.g. forgetting to apply it to
// the second context) gets caught.
func TestScanMultiTargetsInsecureLayering(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})

	// Capture the resolved TLS settings the connector saw for every
	// target. Per-target capture (not global) so an asymmetric
	// regression — flag layered onto first context but not the second
	// — fails loudly.
	type seenContext struct {
		URL      string
		Insecure bool
	}
	var seen []seenContext
	prev := connectFn
	connectFn = func(_ context.Context, cc config.Context) (*client.Client, error) {
		seen = append(seen, seenContext{URL: cc.URL, Insecure: cc.TLS.Insecure})
		switch cc.URL {
		case "http://eu.invalid":
			return healthyClient("eu"), nil
		case "http://us.invalid":
			return healthyClient("us"), nil
		}
		return nil, fmt.Errorf("%w: unknown URL %s", exit.ErrUnreachable, cc.URL)
	}
	t.Cleanup(func() { connectFn = prev })

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan",
		"--insecure",
		"--targets", "prod-eu,prod-us",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("expected 2 connect calls; got %d (%+v)", len(seen), seen)
	}
	for _, s := range seen {
		if !s.Insecure {
			t.Errorf("--insecure should layer onto every target; %s saw Insecure=%v", s.URL, s.Insecure)
		}
	}
}

// TestScanMultiHTMLOutput confirms multi-cluster html renders one
// section per cluster in a single self-contained HTML doc.
func TestScanMultiHTMLOutput(t *testing.T) {
	cfgPath := writeMultiTestConfig(t, map[string]string{
		"prod-eu": "http://eu.invalid",
		"prod-us": "http://us.invalid",
	})
	stubConnectByURL(t, map[string]*client.Client{
		"http://eu.invalid": healthyClient("eu"),
		"http://us.invalid": healthyClient("us"),
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--config", cfgPath, "scan", "--output", "html",
		"--targets", "prod-eu,prod-us",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"<title>esops-doctor fleet scan",
		"prod-eu",
		"prod-us",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("multi-cluster html missing %q\nfull output (truncated):\n%.500s", want, out)
		}
	}
}
