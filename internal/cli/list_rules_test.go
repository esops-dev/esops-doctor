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

	"github.com/esops-dev/esops-doctor/internal/exit"
)

func TestListRulesCommandWiredIntoRoot(t *testing.T) {
	root := newRoot()
	for _, c := range root.Commands {
		if c.Name == "list-rules" {
			return
		}
	}
	t.Fatal("list-rules command not registered on root")
}

func TestListRulesDefaultTable(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{"esops-doctor", "list-rules"}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"ID", "SEVERITY", "CATEGORY", "DIALECTS", "TAGS",
		"heap_size", "critical", "resource_sanity", "elasticsearch,opensearch",
		"rule(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestListRulesJSONOutput(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--output", "json", "list-rules",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Rules         []struct {
			ID       string   `json:"id"`
			Severity string   `json:"severity"`
			Tags     []string `json:"tags"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", doc.SchemaVersion)
	}
	var found bool
	for _, r := range doc.Rules {
		if r.ID == "heap_size" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected heap_size in rules list; got %+v", doc.Rules)
	}
}

func TestListRulesYAMLOutput(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--output", "yaml", "list-rules",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	var doc struct {
		SchemaVersion int `yaml:"schema_version"`
		Rules         []struct {
			ID string `yaml:"id"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not valid yaml: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", doc.SchemaVersion)
	}
}

func TestListRulesRejectsScanOnlyFormat(t *testing.T) {
	for _, fmtName := range []string{"sarif", "junit", "html"} {
		t.Run(fmtName, func(t *testing.T) {
			var stdout bytes.Buffer
			root := newRoot()
			root.Writer = &stdout
			err := root.Run(context.Background(), []string{
				"esops-doctor", "--output", fmtName, "list-rules",
			})
			if err == nil {
				t.Fatalf("expected usage error for --output %s", fmtName)
			}
			if !errors.Is(err, exit.ErrUsage) {
				t.Errorf("err should be ErrUsage; got %v", err)
			}
		})
	}
}

func TestListRulesTagFilter(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "list-rules", "--tags", "performance",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	if !strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("expected heap_size in --tags=performance output; got %q", stdout.String())
	}

	stdout.Reset()
	root = newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "list-rules", "--tags", "nope-not-a-real-tag",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	if !strings.Contains(stdout.String(), "No rules match") {
		t.Errorf("expected empty-result message; got %q", stdout.String())
	}
}

func TestListRulesRuleIDFilter(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "list-rules", "--rule-id", "heap_size",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	if !strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("expected heap_size in --rule-id=heap_size output; got %q", stdout.String())
	}
}

func TestListRulesSkipTagFilter(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "list-rules", "--skip-tags", "performance",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	// heap_size has tag "performance" and should be filtered out.
	if strings.Contains(stdout.String(), "heap_size") {
		t.Errorf("expected heap_size to be filtered out; got %q", stdout.String())
	}
}

func TestListRulesPicksUpRulesDir(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: extra_listed
    name: Extra
    category: extras
    severity: warn
    description: Extra rule from --rules-dir
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
    tags: [extra]
`)
	if err := os.WriteFile(filepath.Join(dir, "extra.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "list-rules", "--rules-dir", dir,
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	if !strings.Contains(stdout.String(), "extra_listed") {
		t.Errorf("expected extra_listed from --rules-dir; got %q", stdout.String())
	}
}

func TestListRulesPicksUpUserRulesDir(t *testing.T) {
	// TestMain pins XDG_CONFIG_HOME to a tempdir so we control where
	// userRulesDir points. Drop a rule there and confirm list-rules
	// surfaces it without a --rules-dir flag — the user-overrides
	// rule-loading path documented in the catalog loader.
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		t.Skip("XDG_CONFIG_HOME not set in test env")
	}
	rulesDir := filepath.Join(xdg, "esops-doctor", "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(xdg, "esops-doctor")) })
	body := []byte(`checks:
  - id: user_override_rule
    name: User Override
    category: extras
    severity: info
    description: Lives in the user rules.d directory.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
`)
	if err := os.WriteFile(filepath.Join(rulesDir, "user.yaml"), body, 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "list-rules",
	}); err != nil {
		t.Fatalf("list-rules: %v", err)
	}
	if !strings.Contains(stdout.String(), "user_override_rule") {
		t.Errorf("expected user_override_rule from user rules.d; got %q", stdout.String())
	}
}
