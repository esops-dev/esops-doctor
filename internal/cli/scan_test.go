package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

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
