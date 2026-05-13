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

// TestNewRuleScaffoldsRuleAndFixture drives the end-to-end happy
// path: scaffold a rule under a temp tree and confirm both files
// exist with the expected structure.
func TestNewRuleScaffoldsRuleAndFixture(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "hygiene")
	fixturesDir := filepath.Join(dir, "testdata", "rule_fixtures")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatalf("mkdir fixtures: %v", err)
	}

	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "new-rule",
		"--rules-root", filepath.Join(dir, "rules"),
		"--fixtures-root", fixturesDir,
		"hygiene/my_check",
	}); err != nil {
		t.Fatalf("new-rule: %v", err)
	}

	rulePath := filepath.Join(rulesDir, "my_check.yaml")
	fixturePath := filepath.Join(fixturesDir, "my_check.yaml")
	ruleBody, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("rule file missing: %v", err)
	}
	fixtureBody, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("fixture file missing: %v", err)
	}

	for _, want := range []string{
		"id: my_check",
		"category: hygiene",
		"severity: warn",
		"probe: cluster_health",
		"TODO summary",
	} {
		if !strings.Contains(string(ruleBody), want) {
			t.Errorf("rule body missing %q", want)
		}
	}
	for _, want := range []string{
		"rule: my_check",
		"expect: pass",
		"expect: fail",
	} {
		if !strings.Contains(string(fixtureBody), want) {
			t.Errorf("fixture body missing %q", want)
		}
	}
}

// TestNewRuleRejectsBadID confirms id validation runs before any
// filesystem work — typos surface at exit 2 (usage), not as half-
// scaffolded files on disk.
func TestNewRuleRejectsBadID(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "new-rule", "hygiene/Heap-Size"})
	if err == nil {
		t.Fatal("expected usage error for invalid rule id")
	}
	if exit.Code(err) != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", exit.Code(err), err)
	}
}

// TestNewRuleRejectsMissingCategoryDir confirms the command refuses
// to write into a category that doesn't exist on disk — that's
// almost always a typo, and silently creating the directory would
// drop a new rule in the wrong place.
func TestNewRuleRejectsMissingCategoryDir(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(), []string{
		"esops-doctor", "new-rule",
		"--rules-root", dir,
		"--fixtures-root", dir,
		"made-up-category/my_check",
	})
	if err == nil {
		t.Fatal("expected usage error for missing category dir")
	}
	if exit.Code(err) != 2 {
		t.Errorf("exit code = %d, want 2; err=%v", exit.Code(err), err)
	}
}

// TestNewRuleRejectsBadSeverity confirms --severity validation
// routes through findings.ParseSeverity (the canonical validator
// the rest of the codebase uses). A typo'd value should fail at
// exit 2, not silently end up in the YAML.
func TestNewRuleRejectsBadSeverity(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "hygiene")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := Run(context.Background(), []string{
		"esops-doctor", "new-rule",
		"--rules-root", filepath.Join(dir, "rules"),
		"--fixtures-root", filepath.Join(dir, "fixtures"),
		"--severity", "blocker",
		"hygiene/test",
	})
	if err == nil {
		t.Fatal("expected usage error for unknown severity")
	}
	if exit.Code(err) != 2 {
		t.Errorf("exit code = %d, want 2", exit.Code(err))
	}
}

// TestNewRuleRefusesToOverwriteWithoutForce confirms an existing
// rule file is preserved unless --force is set.
func TestNewRuleRefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules", "hygiene")
	fixturesDir := filepath.Join(dir, "testdata", "rule_fixtures")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatalf("mkdir fixtures: %v", err)
	}
	preExisting := filepath.Join(rulesDir, "existing.yaml")
	if err := os.WriteFile(preExisting, []byte("pre-existing content\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	err := Run(context.Background(), []string{
		"esops-doctor", "new-rule",
		"--rules-root", filepath.Join(dir, "rules"),
		"--fixtures-root", fixturesDir,
		"hygiene/existing",
	})
	if err == nil {
		t.Fatal("expected refusal to overwrite without --force")
	}
	got, _ := os.ReadFile(preExisting)
	if string(got) != "pre-existing content\n" {
		t.Errorf("pre-existing rule body was clobbered: %q", string(got))
	}
}
