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

func TestExplainCommandWiredIntoRoot(t *testing.T) {
	root := newRoot()
	for _, c := range root.Commands {
		if c.Name == "explain" {
			return
		}
	}
	t.Fatal("explain command not registered on root")
}

func TestExplainKnownRuleTextOutput(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "explain", "heap_size",
	}); err != nil {
		t.Fatalf("explain: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"heap_size — JVM heap size configuration",
		"severity: critical",
		"category: resource_sanity",
		"Description:",
		"Condition (CEL):",
		"Message template:",
		"Remediation:",
		"https://www.elastic.co/guide/en/elasticsearch/reference/current/heap-size.html",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain text output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestExplainJSONOutput(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--output", "json", "explain", "heap_size",
	}); err != nil {
		t.Fatalf("explain: %v", err)
	}
	var entry struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Condition   string `json:"condition"`
		Remediation struct {
			DocURL string `json:"doc_url"`
		} `json:"remediation"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &entry); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, stdout.String())
	}
	if entry.ID != "heap_size" {
		t.Errorf("id = %q, want heap_size", entry.ID)
	}
	if entry.Severity != "critical" {
		t.Errorf("severity = %q, want critical", entry.Severity)
	}
	if entry.Condition == "" {
		t.Error("condition should be populated")
	}
	if entry.Remediation.DocURL == "" {
		t.Error("remediation.doc_url should be populated")
	}
}

func TestExplainYAMLOutput(t *testing.T) {
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "--output", "yaml", "explain", "heap_size",
	}); err != nil {
		t.Fatalf("explain: %v", err)
	}
	var entry struct {
		ID       string `yaml:"id"`
		Severity string `yaml:"severity"`
	}
	if err := yaml.Unmarshal(stdout.Bytes(), &entry); err != nil {
		t.Fatalf("not valid yaml: %v\n%s", err, stdout.String())
	}
	if entry.ID != "heap_size" {
		t.Errorf("id = %q, want heap_size", entry.ID)
	}
}

func TestExplainUnknownRuleIsUsageError(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "explain", "no_such_rule"})
	if err == nil {
		t.Fatal("expected error for unknown rule")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err should be ErrUsage; got %v", err)
	}
}

func TestExplainMissingArgIsUsageError(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "explain"})
	if err == nil {
		t.Fatal("expected error when RULE_ID is missing")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err should be ErrUsage; got %v", err)
	}
}

func TestExplainTooManyArgsIsUsageError(t *testing.T) {
	err := Run(context.Background(), []string{"esops-doctor", "explain", "heap_size", "extra"})
	if err == nil {
		t.Fatal("expected error when more than one RULE_ID arg")
	}
	if !errors.Is(err, exit.ErrUsage) {
		t.Errorf("err should be ErrUsage; got %v", err)
	}
}

// TestExplainSurfacesEsopsCommands guards that explain --output text
// prints any esops_commands defined on the rule under the Remediation
// section, and that JSON consumers see the same field on the
// remediation object. cluster_health_status is the canonical rule
// shipping these in the embedded catalog.
func TestExplainSurfacesEsopsCommands(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		var stdout bytes.Buffer
		root := newRoot()
		root.Writer = &stdout
		if err := root.Run(context.Background(), []string{
			"esops-doctor", "explain", "cluster_health_status",
		}); err != nil {
			t.Fatalf("explain: %v", err)
		}
		out := stdout.String()
		for _, want := range []string{
			"esops_commands:",
			"esops ops health",
			"esops ops shards",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("explain text output missing %q\nfull output:\n%s", want, out)
			}
		}
	})
	t.Run("json", func(t *testing.T) {
		var stdout bytes.Buffer
		root := newRoot()
		root.Writer = &stdout
		if err := root.Run(context.Background(), []string{
			"esops-doctor", "--output", "json", "explain", "cluster_health_status",
		}); err != nil {
			t.Fatalf("explain: %v", err)
		}
		var entry struct {
			Remediation struct {
				EsopsCommands []string `json:"esops_commands"`
			} `json:"remediation"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &entry); err != nil {
			t.Fatalf("not valid json: %v\n%s", err, stdout.String())
		}
		if len(entry.Remediation.EsopsCommands) == 0 {
			t.Errorf("remediation.esops_commands should be populated; got %v", entry.Remediation.EsopsCommands)
		}
	})
}

func TestExplainResolvesAlias(t *testing.T) {
	// Build a rules-dir with a rule carrying a deprecated_alias and
	// confirm explain ALIAS_NAME finds the canonical rule.
	dir := t.TempDir()
	body := []byte(`checks:
  - id: canonical_rule
    name: Canonical
    category: extras
    severity: warn
    description: Demonstrates alias resolution.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch]
    deprecated_aliases: [old_name]
`)
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	root := newRoot()
	root.Writer = &stdout
	if err := root.Run(context.Background(), []string{
		"esops-doctor", "explain", "old_name", "--rules-dir", dir,
	}); err != nil {
		t.Fatalf("explain: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "canonical_rule") {
		t.Errorf("expected canonical_rule in output; got %q", out)
	}
	if !strings.Contains(out, `resolved from deprecated alias "old_name"`) {
		t.Errorf("expected alias-resolution note; got %q", out)
	}
}

func TestExplainRejectsScanOnlyFormat(t *testing.T) {
	for _, fmtName := range []string{"sarif", "junit", "html"} {
		t.Run(fmtName, func(t *testing.T) {
			err := Run(context.Background(), []string{
				"esops-doctor", "--output", fmtName, "explain", "heap_size",
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
