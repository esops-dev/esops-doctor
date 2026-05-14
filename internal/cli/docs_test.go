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

func TestDocsRulesEmbeddedCatalog(t *testing.T) {
	if err := Run(context.Background(), []string{"esops-doctor", "docs", "rules"}); err != nil {
		t.Fatalf("Run(docs rules): %v", err)
	}
}

func TestDocsRulesWritesToOutputFile(t *testing.T) {
	target := filepath.Join(t.TempDir(), "rules.md")
	if err := Run(context.Background(), []string{
		"esops-doctor", "docs", "rules",
		"--output-file", target,
	}); err != nil {
		t.Fatalf("Run(docs rules --output-file): %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	got := string(body)
	if !strings.HasPrefix(got, "# Rule reference") {
		t.Errorf("missing markdown header; got first 80 bytes %q", trimForMessage(got, 80))
	}
	if !strings.Contains(got, "## Table of contents") {
		t.Errorf("missing TOC; got %d bytes", len(got))
	}
	if !strings.Contains(got, "**Condition (CEL):**") {
		t.Errorf("missing CEL section; got %d bytes", len(got))
	}
}

func TestDocsRulesIncludesRulesDir(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`checks:
  - id: docs_extra_rule
    name: Extra rule from --rules-dir
    category: extras
    severity: info
    description: Layered onto the embedded catalog so docs render it.
    probe: nodes
    condition: "true"
    message: m
    dialects: [elasticsearch, opensearch]
`)
	if err := os.WriteFile(filepath.Join(dir, "extra.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "rules.md")
	if err := Run(context.Background(), []string{
		"esops-doctor", "docs", "rules",
		"--rules-dir", dir,
		"--output-file", target,
	}); err != nil {
		t.Fatalf("Run(docs rules --rules-dir): %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if !strings.Contains(string(got), "docs_extra_rule") {
		t.Errorf("extra rule id missing from rendered markdown")
	}
}

func TestDocsRulesFailsOnBadRulesDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	err := Run(context.Background(), []string{
		"esops-doctor", "docs", "rules",
		"--rules-dir", missing,
	})
	if err == nil {
		t.Fatal("expected error for missing rules-dir")
	}
	if !errors.Is(err, exit.ErrCatalog) {
		t.Errorf("err should be ErrCatalog; got %v", err)
	}
}

func TestDocsSchemasListWithoutFlag(t *testing.T) {
	var buf bytes.Buffer
	cmd := newRoot()
	cmd.Writer = &buf
	if err := cmd.Run(context.Background(), []string{"esops-doctor", "docs", "schemas"}); err != nil {
		t.Fatalf("Run(docs schemas): %v", err)
	}
	out := buf.String()
	for _, want := range []string{"rule.schema.json", "profile.schema.json", "waiver.schema.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected listing to contain %q; got %q", want, out)
		}
	}
}

func TestDocsSchemasWriteToDir(t *testing.T) {
	dir := t.TempDir()
	if err := Run(context.Background(), []string{
		"esops-doctor", "docs", "schemas",
		"--output-dir", dir,
	}); err != nil {
		t.Fatalf("Run(docs schemas --output-dir): %v", err)
	}
	for _, name := range []string{"rule.schema.json", "profile.schema.json", "waiver.schema.json"} {
		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("%s is not valid JSON: %v", name, err)
		}
		if _, ok := doc["$schema"]; !ok {
			t.Errorf("%s missing $schema", name)
		}
	}
}

func TestDocsRulesCommandWiredIntoRoot(t *testing.T) {
	root := newRoot()
	for _, c := range root.Commands {
		if c.Name == "docs" {
			for _, sub := range c.Commands {
				if sub.Name == "rules" {
					return
				}
			}
			t.Fatal("docs command found but `rules` subcommand missing")
		}
	}
	t.Fatal("docs command not wired into root")
}

func trimForMessage(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
