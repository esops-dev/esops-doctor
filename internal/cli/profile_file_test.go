package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/esops-dev/esops-go/pkg/client"
	"github.com/esops-dev/esops-go/pkg/types"

	"github.com/esops-dev/esops-doctor/internal/exit"
)

// TestScanProfileAndProfileFileMutuallyExclusive — passing both flags
// is a usage error, not a precedence rule. Exclusion is enforced at
// applyProfile so the message is reachable regardless of cluster
// reachability.
func TestScanProfileAndProfileFileMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	profPath := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(profPath, []byte(`name: x
`), 0o600); err != nil {
		t.Fatal(err)
	}

	stubConnect(t, &client.Client{
		Info: types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
	})

	err := Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--profile", "prod",
		"--profile-file", profPath,
		"--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected error when both --profile and --profile-file are set")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("expected ErrUsage; got %v (code=%d)", err, exit.Code(err))
	}
}

// TestScanProfileFileMissingPathIsUsageError — an explicit
// --profile-file that doesn't exist exits 2, mirroring the --waivers
// behaviour. Operators who type a path expect it to exist; silent
// fallback to defaults would mask typos.
func TestScanProfileFileMissingPathIsUsageError(t *testing.T) {
	stubConnect(t, &client.Client{
		Info: types.ClusterInfo{Dialect: types.DialectElasticsearch, ClusterName: "test", Version: "9.0.0"},
	})
	err := Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--profile-file", "/no/such/profile.yaml",
		"--url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected usage error for missing profile-file path")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("expected ErrUsage; got %v (code=%d)", err, exit.Code(err))
	}
}

// TestScanProfileFileAppliesSeverityOverride — a --profile-file with
// `severity_overrides: { heap_size: info }` should demote the rule's
// severity below the default --fail-on threshold of "error", so a
// scan that would otherwise exit 20 exits clean.
func TestScanProfileFileAppliesSeverityOverride(t *testing.T) {
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
	profPath := filepath.Join(dir, "demote.yaml")
	body := []byte(`name: demote
description: Custom profile demoting heap_size below the fail threshold.
severity_overrides:
  heap_size: info
`)
	if err := os.WriteFile(profPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	err := root.Run(context.Background(), []string{
		"esops-doctor", "scan",
		"--profile-file", profPath,
		"--rule-id", "heap_size",
		"--url", "http://example.invalid",
	})
	if err != nil {
		t.Fatalf("expected demoted heap_size to keep the scan below the threshold; got %v\noutput=%s",
			err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("expected heap_size to still appear in output (just demoted); got %q", stdout.String())
	}
}

// fakeNodeStatsInspector satisfies node_stats so heap_size has data
// to evaluate against — the existing version in scan_test.go is in
// the same package, but a duplicate here would shadow it; this test
// reuses that one.

// TestNewProfileEmitsSkeletonWithEmbeddedRules — `new-profile` writes
// a YAML skeleton on stdout listing every embedded rule as a
// commented-out severity_overrides entry. The test invokes the
// command through the urfave plumbing (root.Run) and asserts on the
// captured output.
func TestNewProfileEmitsSkeletonWithEmbeddedRules(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "new-profile",
	}); err != nil {
		t.Fatalf("new-profile: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"name: custom",
		"severity_overrides:",
		"include_tags: []",
		"skip_tags: []",
		"rule_ids: []",
		"# heap_size:",
		"# security_disabled:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("skeleton missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestNewProfileHonoursName — --name customises the generated
// `name:` field. The flag exists so an operator gets a usable
// identifier in the YAML they're about to commit, without a
// post-generation sed.
func TestNewProfileHonoursName(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "new-profile", "--name", "fleet-prod",
	}); err != nil {
		t.Fatalf("new-profile: %v", err)
	}
	if !strings.Contains(stdout.String(), "name: fleet-prod") {
		t.Errorf("expected `name: fleet-prod` in output; got %q", stdout.String())
	}
}

// TestNewProfileIncludesRulesDirOverride — when --rules-dir layers a
// rule that overrides an embedded ID, the skeleton lists the
// overridden rule once (with the operator's severity), not twice.
// Same guarantee as the catalog override test, exercised through the
// new-profile command.
func TestNewProfileIncludesRulesDirOverride(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: heap_size
    name: Operator heap_size
    category: resource_sanity
    severity: info
    description: override
    probe: node_stats
    condition: "true"
    message: m
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "heap_size.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "new-profile", "--rules-dir", dir,
	}); err != nil {
		t.Fatalf("new-profile: %v", err)
	}
	got := stdout.String()
	count := strings.Count(got, "# heap_size:")
	if count != 1 {
		t.Errorf("expected heap_size to appear exactly once after override; got %d\n--- output ---\n%s",
			count, got)
	}
	if !strings.Contains(got, "# heap_size: info") {
		t.Errorf("expected the operator-supplied severity (info) in the skeleton; got %q", got)
	}
}
