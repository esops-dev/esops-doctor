package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"
)

// TestScanNoColorFlagSuppressesANSI confirms --no-color produces an
// ANSI-free table on the failing-finding path. The default for a
// non-TTY stdout (a bytes.Buffer in tests) is already off, so this
// test additionally pins CLICOLOR_FORCE=1 to prove --no-color wins
// over a forced-on env.
func TestScanNoColorFlagSuppressesANSI(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	overSized := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 32 * gb, MaxBytes: 32 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 64 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "t", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{overSized}},
	})

	t.Setenv("CLICOLOR_FORCE", "1")

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	_ = root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--no-color", "--url", "http://example.invalid",
	})

	if strings.Contains(stdout.String(), "\x1b[") {
		t.Errorf("--no-color should suppress ANSI escapes; got escape sequence in output:\n%s", stdout.String())
	}
}

// TestScanIncludePassedSurfacesPassRows confirms --include-passed
// emits a "passed (N)" block listing the rules that ran cleanly.
// Default behaviour is to drop those rows; this is the operator-
// facing opt-in for the "what was checked" report.
func TestScanIncludePassedSurfacesPassRows(t *testing.T) {
	const gb = int64(1024 * 1024 * 1024)
	healthy := types.NodeStats{
		Name: "n1",
		JVM:  types.NodeJVMStats{Heap: types.NodeJVMHeap{InitBytes: 8 * gb, MaxBytes: 8 * gb}},
		OS:   types.NodeOSStats{TotalPhysicalMemoryBytes: 32 * gb},
	}
	stubConnect(t, &client.Client{
		Info:      types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "t", Version: "9.0.0"},
		NodeStats: &fakeNodeStatsInspector{Result: []types.NodeStats{healthy}},
	})

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "scan", "--include-passed", "--url", "http://example.invalid",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "passed (1)") {
		t.Errorf("expected passed section header; got %q", out)
	}
	if !strings.Contains(out, "heap_size") {
		t.Errorf("expected the passing rule id in the passed section; got %q", out)
	}
}

// TestScanRejectsNegativePrefetchConcurrency confirms a negative
// --prefetch-concurrency fails at exit 2 (usage) before any cluster
// contact is attempted.
func TestScanRejectsNegativePrefetchConcurrency(t *testing.T) {
	err := Run(context.Background(), []string{
		"esops-doctor", "scan", "--prefetch-concurrency", "-1", "--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected usage error for negative --prefetch-concurrency")
	}
	if !strings.Contains(err.Error(), "prefetch-concurrency") {
		t.Errorf("err should call out the offending flag; got %v", err)
	}
}
