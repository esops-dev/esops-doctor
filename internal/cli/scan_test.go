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

	yaml "go.yaml.in/yaml/v3"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/config"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// fakeNodeStatsInspector is the minimum capability the embedded
// heap_size rule's `node_stats` probe needs. The stub returns one
// healthy node so the rule passes; tests asserting failure paths
// override Result.
type fakeNodeStatsInspector struct{ Result []types.NodeStats }

func (f *fakeNodeStatsInspector) NodeStats(context.Context) ([]types.NodeStats, error) {
	return f.Result, nil
}

// stubConnect installs a connector that returns a synthetic *client.Client
// for the duration of the test. Restores the previous connector via
// t.Cleanup so a panicking test doesn't leak the stub into subsequent
// tests within the same package.
func stubConnect(t *testing.T, cl *client.Client) {
	t.Helper()
	prev := connectFn
	connectFn = func(context.Context, config.Context) (*client.Client, error) {
		return cl, nil
	}
	t.Cleanup(func() { connectFn = prev })
}

func TestScanCommandWiredIntoRoot(t *testing.T) {
	root := newRoot()
	for _, c := range root.Commands {
		if c.Name == "scan" {
			return
		}
	}
	t.Fatal("scan command not registered on root")
}

func TestScanRejectsBadFailOn(t *testing.T) {
	// --fail-on "trace" is not a recognised severity. Validator must
	// reject before we attempt cluster connect, so this surfaces as
	// exit 2 (usage) rather than exit 3 (unreachable).
	err := Run(context.Background(), []string{"esops-doctor", "scan", "--fail-on", "trace"})
	if err == nil {
		t.Fatal("expected validation error for --fail-on=trace")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err should match ErrUsage; got %v (Code=%d)", err, exit.Code(err))
	}
}

func TestScanWithoutContextOrUrlFails(t *testing.T) {
	// No --url, no --context, no config file in the test env (TestMain
	// pins paths into an empty TempDir). The resolver returns a usage
	// error pointing at the missing config — exit 2.
	err := Run(context.Background(), []string{"esops-doctor", "scan"})
	if err == nil {
		t.Fatal("expected error when no context can be resolved")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (usage); err=%v", got, err)
	}
}

func TestScanUnreachableClusterMapsToExit3(t *testing.T) {
	// Point --url at a port nothing listens on. probes.Connect translates
	// the upstream client.ErrUnreachable into exit.ErrUnreachable, which
	// the exit code mapper renders as 3.
	//
	// 127.0.0.1:1 is the conventional "always-refused" address — RFC 6335
	// reserves port 0 ("never assigned"), but Go disallows it for dial
	// targets, so port 1 is the next-best option. The connect must fail
	// fast even on slow CI; pkg/cluster's probe applies effectiveTimeout
	// from the context.
	err := Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--url", "http://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("expected unreachable error")
	}
	if got := exit.Code(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (cluster unreachable); err=%v", got, err)
	}
}

// TestScanSuccessPath drives runScan end-to-end with a stubbed
// connector that returns a synthetic *client.Client wired with the
// node_stats capability the embedded heap_size rule needs. Asserts
// the engine evaluates, the table renders, and the exit is clean
// (exit 0) when no finding fires.
//
// Without this test, runScan's evaluate → render → exit-determination
// path would only have coverage when a real cluster is reachable
// (integration tests) — leaving the cli wiring uncovered on every
// fast-path PR. The stub is the smallest seam that exercises the
// post-connect logic.
func TestScanSuccessPath(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthyNode := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthyNode}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{"esops-doctor", "scan", "--url", "http://example.invalid"}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"no findings against elasticsearch",
		"summary: 0 critical",
		"1 passed",
		`cluster="test"`,
		"elasticsearch 9.0.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestScanFailingFindingExitsTwenty drives the failure path: a probe
// returns data that makes the heap_size rule fire, and the scan exits
// with ErrFindings (code 20). The threshold is left at the default
// (--fail-on=error), so the rule's "critical" finding passes the gate.
func TestScanFailingFindingExitsTwenty(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{"esops-doctor", "scan", "--url", "http://example.invalid"})
	if err == nil {
		t.Fatal("expected ErrFindings on critical heap-size violation")
	}
	if got := exit.Code(err); got != 20 {
		t.Errorf("exit code = %d, want 20 (findings); err=%v", got, err)
	}
	if !strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("stdout should include the failing rule id; got %q", stdout.String())
	}
}

// TestScanJSONOutput exercises the json renderer end-to-end through the
// scan command: stub a healthy cluster, run with --output json, and
// confirm the bytes are valid JSON carrying the documented schema. The
// renderer's own tests cover field-by-field shape — this test's job is
// to prove the cli wired the format flag through to report.Render.
func TestScanJSONOutput(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--output", "json", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Cluster       struct {
			Name    string `json:"name"`
			Dialect string `json:"dialect"`
		} `json:"cluster"`
		Summary struct {
			Passed int `json:"passed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", doc.SchemaVersion)
	}
	if doc.Cluster.Name != "prod-eu" || doc.Cluster.Dialect != "elasticsearch" {
		t.Errorf("cluster = %+v", doc.Cluster)
	}
	if doc.Summary.Passed != 1 {
		t.Errorf("summary.passed = %d, want 1", doc.Summary.Passed)
	}
}

// TestScanYAMLOutput is the YAML twin of TestScanJSONOutput: same
// scenario, different format, asserts the wire shape round-trips.
func TestScanYAMLOutput(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--output", "yaml", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var doc struct {
		SchemaVersion int `yaml:"schema_version"`
		Cluster       struct {
			Dialect string `yaml:"dialect"`
		} `yaml:"cluster"`
	}
	if err := yaml.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid yaml: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", doc.SchemaVersion)
	}
	if doc.Cluster.Dialect != "elasticsearch" {
		t.Errorf("cluster.dialect = %q", doc.Cluster.Dialect)
	}
}

// TestScanSARIFOutput exercises the sarif renderer end-to-end through
// the scan command: stub a healthy cluster, run with --output sarif,
// and confirm the bytes are valid SARIF 2.1.0 carrying the tool
// driver block. The renderer's own tests cover field-by-field shape;
// this test's job is to prove the cli wired the format flag through.
func TestScanSARIFOutput(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--output", "sarif", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid sarif json: %v\n%s", err, stdout.String())
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("sarif.version = %v, want 2.1.0", doc["version"])
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	driver := runs[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "esops-doctor" {
		t.Errorf("driver.name = %v, want esops-doctor", driver["name"])
	}
}

// TestScanJUnitOutput is the JUnit twin of TestScanSARIFOutput: same
// scenario, different format, asserts the wire shape parses.
func TestScanJUnitOutput(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--output", "junit", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	if !strings.HasPrefix(out, `<?xml version="1.0"`) {
		t.Errorf("junit output should start with XML header; got %.40q", out)
	}
	for _, want := range []string{
		`<testsuites`, `<testsuite`, `<testcase`, `name="heap_size"`, `tests="1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("junit output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestScanHTMLOutput exercises the html renderer end-to-end through
// the scan command. The renderer's own tests cover well-formedness;
// this test's job is to prove the cli wired the format through and
// that the document carries cluster identity in the page chrome.
func TestScanHTMLOutput(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--output", "html", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"<title>esops-doctor scan",
		"prod-eu",
		"elasticsearch 9.0.0",
		"heap_size",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html output missing %q\nfull output (truncated):\n%.500s", want, out)
		}
	}
}

// TestScanRejectsUnknownFormat confirms a value not in the known
// format set fails fast with exit 2 (usage), not exit 1 (generic).
// `xml` is a plausible typo for `yaml` — it must be caught before any
// cluster work happens.
func TestScanRejectsUnknownFormat(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "scan", "--output", "xml", "--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected usage error for --output xml")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", got, err)
	}
}

// TestScanRejectsUnknownProfile confirms a typo'd --profile fails fast
// with exit 2, before any cluster work happens.
func TestScanRejectsUnknownProfile(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "scan", "--profile", "prdo", "--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", got, err)
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("err should call out unknown profile; got %v", err)
	}
}

// TestScanProfileFiltersAndOverridesSeverity drives the prod profile
// against a healthy cluster and asserts the rule still passes (the
// override only changes severity for fails). Then drives the dev
// profile against the failing-heap fixture: dev does not override
// heap_size's severity, so the failure is still critical and the exit
// is 20.
//
// The point of this test is the integration handshake — proves the
// scan command loaded the embedded profile catalog and threaded the
// selected profile through to engine.Compile via applyProfile.
func TestScanProdProfilePassesOnHealthyCluster(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "prod-eu", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--profile", "prod", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(stdout.String(), "1 passed") {
		t.Errorf("expected 1 passed; got %q", stdout.String())
	}
}

// TestScanCisBenchProfileFiltersHeapRule confirms the cis-bench profile
// narrows the catalog by include_tags. heap_size has tags
// [prod, performance] — neither matches [security, bootstrap, cis-bench],
// so cis-bench should drop heap_size from the run, leaving zero rules
// to evaluate. The exit code is 0 because nothing failed.
func TestScanCisBenchProfileFiltersHeapRule(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--profile", "cis-bench", "--url", "http://example.invalid",
	})
	if err != nil {
		t.Fatalf("expected clean exit when cis-bench filters out the failing rule; got %v", err)
	}
}

// TestScanWaiverSuppressesFailingFinding loads a waivers file that
// covers heap_size and confirms the failing scan now exits 0 instead
// of 20 — the operator's documented suppression cleared the gate.
func TestScanWaiverSuppressesFailingFinding(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	dir := t.TempDir()
	waiverPath := filepath.Join(dir, "w.yaml")
	if err := os.WriteFile(waiverPath, []byte(`
waivers:
  - rule_id: heap_size
    justification: Approved by SRE
    expires_at: 2099-12-31
`), 0o600); err != nil {
		t.Fatalf("write waivers: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--waivers", waiverPath, "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan with waiver should pass; got %v", err)
	}
	if !strings.Contains(stdout.String(), "1 waived") {
		t.Errorf("summary should report 1 waived; got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Approved by SRE") {
		t.Errorf("waived section should show justification; got %q", stdout.String())
	}
}

// TestScanExpiredWaiverFailsLoud — the CLAUDE.md §9 contract:
// expired waivers re-surface the finding, prefixed with the expired
// note, and the scan still exits 20.
func TestScanExpiredWaiverFailsLoud(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	dir := t.TempDir()
	waiverPath := filepath.Join(dir, "w.yaml")
	if err := os.WriteFile(waiverPath, []byte(`
waivers:
  - rule_id: heap_size
    justification: was approved but lapsed
    expires_at: 2024-01-01
`), 0o600); err != nil {
		t.Fatalf("write waivers: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--waivers", waiverPath, "--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected ErrFindings; expired waiver must not suppress the failure")
	}
	if got := exit.Code(err); got != 20 {
		t.Errorf("exit code = %d, want 20; err=%v", got, err)
	}
	if !strings.Contains(stdout.String(), "[waiver expired 2024-01-01]") {
		t.Errorf("expected expired-waiver prefix in output; got %q", stdout.String())
	}
}

// TestScanMissingWaiversFileIsUsageError — an explicit --waivers PATH
// that does not exist should fail fast at exit 2, before any cluster
// work happens. (The default file lookup, by contrast, silently
// returns no waivers — see TestLoadDefaultReturnsNilWhenNothingFound
// in the waivers package.)
func TestScanMissingWaiversFileIsUsageError(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "scan", "--waivers", "/nonexistent/path/waivers.yaml",
		"--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected error for missing waivers path")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", got, err)
	}
}

// TestScanClusterWaiversFlagIsDocumentedButGated reflects the current
// state: --cluster-waivers is reserved (the user story is on the
// roadmap) but pkg/client does not yet expose the document-read
// capability needed to implement it. The flag returns a usage error
// pointing at the upstream gap rather than silently no-op'ing.
func TestScanClusterWaiversFlagIsDocumentedButGated(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "scan", "--cluster-waivers", "--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected usage error explaining the upstream gap")
	}
	if got := exit.Code(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", got, err)
	}
	if !strings.Contains(err.Error(), "cluster-waivers") ||
		!strings.Contains(err.Error(), "pkg/client") {
		t.Errorf("err should explain the upstream pkg/client gap; got %v", err)
	}
}

func TestScanHelpDescribesExitCodes(t *testing.T) {
	// --help is the v0.1 documentation surface (CLAUDE.md §13). Confirm
	// the scan command surfaces the exit-code semantics there so
	// operators don't have to read the source to find them.
	root := newRoot()
	var sc string
	for _, c := range root.Commands {
		if c.Name == "scan" {
			sc = c.Description
		}
	}
	if !strings.Contains(sc, "Exit code 20") {
		t.Errorf("scan description should explain exit 20; got %q", sc)
	}
	if !strings.Contains(sc, "3/4/5/10") {
		t.Errorf("scan description should explain cluster-side codes; got %q", sc)
	}
}
